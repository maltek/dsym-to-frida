#!/usr/bin/env python

from __future__ import absolute_import, division, print_function, unicode_literals

import fnmatch
import os
import re
import sys
import optparse
import shlex

import lldb


def create_types_options():
    usage = "usage: %prog [options] EXEPATH [EXEPATH ...]"
    description = '''This command will help check for padding in between
base classes and members in structures and classes. It will summarize the types
and how much padding was found. One or more paths to executable files must be
specified and targets will be created with these modules. If no types are
specified with the --types TYPENAME option, all structure and class types will
be verified in all specified modules.
'''
    parser = optparse.OptionParser(
        description=description,
        prog='framestats',
        usage=usage)
    parser.add_option(
        '-a',
        '--arch',
        type='string',
        dest='arch',
        help='The architecture to use when creating the debug target.',
        default=None)
    parser.add_option(
        '-p',
        '--platform',
        type='string',
        metavar='platform',
        dest='platform',
        help='Specify the platform to use when creating the debug target. Valid values include "localhost", "darwin-kernel", "ios-simulator", "remote-freebsd", "remote-macosx", "remote-ios", "remote-linux".')
    parser.add_option(
        '-t',
        '--type',
        type='string',
        metavar='type_glob',
        dest='type_glob',
        help='Only include types whose name matches type_glob.')
    return parser


def sanitize_name(type):
    name = type.name
    # remove template parameters. don't generate handlers for more than one instantiation!
    while "<" in name:
        start = name.index("<")
        num_open = 1
        for i, c in enumerate(name[start+1:], start+1):
            if c == "<":
                num_open += 1
            if c == ">":
                num_open -= 1
                if num_open == 0:
                    break
        name = name[:start] + name[i+1:]

    # namespaces
    name = name.split("::")
    return ".".join(name[:-1]), name[-1]

def camel_case(name):
    # keep all-caps constants as-is
    if name.upper() == name:
        return name

    pre = ""
    while name[0] == "_":
        pre += "_"
        name = name[1:]

    elems = ((s[0].lower() if i == 0 else s[0].upper()) + s[1:] for i, s in enumerate(name.split("_")))
    return pre + "".join(elems)


def print_type(target, type, generated_types):
    #print('/*%s*/' % type)
    namespace, san_name = sanitize_name(type)
    if namespace:
        print("namespace %s {" % namespace)

    print("    // " + type.name)

    if type.GetTypeClass() == lldb.eTypeClassEnumeration:
        print('    export const %s = {' % san_name)
        members = type.GetEnumMembers()
        members = [members.GetTypeEnumMemberAtIndex(i) for i in range(members.GetSize())]
        for member in members:
            print('''        "{0}": {1},
        "{1}": "{0}",'''.format(member.name, member.unsigned))
        print("        sizeof: {}".format(type.size))
        print('    };')
        if namespace:
            print("}")
        return

    print('    export class %s {' % san_name)
    print('        constructor(_ptr) { this._ptr = _ptr; }')

    members = type.members
    if type.IsPolymorphicClass() and (not members or members[0].byte_offset == target.GetAddressByteSize()):
        ptr_size = target.GetAddressByteSize()
        print('       0 <%3u> __vtbl_ptr_type * _vptr;' % ptr_size)

    for member_idx, member in enumerate(members):
        member_type_class = member.type.GetCanonicalType().GetTypeClass()
        is_class_or_struct = member_type_class in (lldb.eTypeClassStruct, lldb.eTypeClassClass)
        is_primitive = member_type_class in (lldb.eTypeClassBuiltin, lldb.eTypeClassEnumeration)

        if is_primitive:
            signed = 'U' if member.type.name.startswith('unsigned ') else 'S'
            bit_mask = 1**member.bitfield_bit_size-1
            if member.type.size <= 4:
                fmt = '        get %s() { return (Memory.read%c%u(this._ptr.add(%u)) >>> %u)%s; }'
                bit_mask = ' & ' + hex(bit_mask) if bit_mask else ''
            else:
                fmt = '        get %s() { return Memory.read%c%u(this._ptr.add(%u)).shr(%u)%s; }'
                bit_mask = '.and(' + hex(bit_mask) + ')' if bit_mask else ''
            type_bit_size = member.type.size * 8
            print(fmt % (camel_case(member.name), signed, type_bit_size, member.byte_offset,
                         member.bit_offset % 8, bit_mask))
            if member.bit_offset % 8 == 0 and member.bitfield_bit_size == 0:
                fmt = '        set %s(val) { Memory.write%c%u(this._ptr.add(%u), val); }'
                print(fmt % (camel_case(member.name), signed, type_bit_size, member.byte_offset))
        elif is_class_or_struct:
            fmt = '        get %s() { return new %s(this._ptr.add(%u)); }'
            print(fmt % (camel_case(member.name), ".".join(sanitize_name(member.type)), member.byte_offset))
        elif member.type.is_pointer or member.type.is_reference:
            pointee = member.type.GetPointeeType()
            if pointee.name in generated_types:
                type_fn = 'new {}'.format(pointee.name)
                from_high_level = 'val instanceof {} ? val._ptr : val instanceof NativePointer ? val : throw new Error("got value of wrong type")'.format(pointee.name)
            else:
                type_fn = ''
                from_high_level = 'val'
            fmt = '''        get {0}() {{
            return {2}(Memory.readPointer(this._ptr.add({1})));
        }}
        set {0}(val) {{
            Memory.writePointer(this._ptr.add({1}), {3});
        }}'''
            print(fmt.format(camel_case(member.name), member.byte_offset, type_fn, from_high_level))
    print('    }')
    print('    %s.sizeof = %u;' % (sanitize_name(type)[1], type.size))
    if namespace:
        print("}")
    print()


def main():
    parser = create_types_options()

    options, args = parser.parse_args(sys.argv[1:])

    for path in args:
        debugger = lldb.SBDebugger.Create()
        error = lldb.SBError()
        target = debugger.CreateTarget(str(path), str(options.arch), str(options.platform), True, error)
        if error.Fail():
            print(error.description)
            continue
        target.AddModule('/Users/malte/Library/Developer/Xcode/DerivedData/SwiftFridaTests-fdzgqlqfpbydbcbaswxptmrprxwe/Build/Products/Debug-iphoneos/SwiftFridaTests.app/Frameworks/libswiftCore.dylib', 'ios-remote', None, '/Users/malte/Library/Developer/Toolchains/swift-LOCAL-2019-06-23-a.xctoolchain//usr/lib/swift/iphoneos/libswiftCore.dylib.dSYM')

        matched_types = {}
        for module in target.modules:
            print('module: %s' % (module.file))
            types = module.GetTypes(lldb.eTypeClassClass | lldb.eTypeClassStruct | lldb.eTypeClassEnumeration)
            for type in types:
                if fnmatch.fnmatchcase(type.name, str(options.type_glob or '*')):
                    assert type.name not in matched_types
                    matched_types[type.name] = type

        for type in matched_types.values():
            print_type(target, type, matched_types.keys())

def find_matches(command):
    args = shlex.split(command) or ['*']
    found = {}
    for module in lldb.debugger.GetSelectedTarget().modules:
        types = module.GetTypes()
        for type in types:
            while type.is_pointer or type.is_reference:
                if type.is_reference:
                    type = type.GetDereferencedType()
                if type.is_pointer:
                    type = type.GetPointeeType()
            type = type.GetUnqualifiedType().GetCanonicalType()
            name = type.name
            #if not type.is_complete:
            #    continue
            if name in found:
                continue
            for glob in args:
                if fnmatch.fnmatchcase(name, glob):
                    found[name] = type
                    break
    return found


def list_types(debugger, command, result, dict):
    for name in find_matches(command).keys():
        print(name)

def dump_type(debugger, command, result, dict):
    generated = find_matches(command)
    for type in generated.values():
        print_type(lldb.target, type, generated.keys())

def __lldb_init_module(debugger, internal_dict):
    for cmd in ['list_types', 'dump_type']:
        res = lldb.SBCommandReturnObject()
        debugger.GetCommandInterpreter().HandleCommand(b'command script add -f {0}.{1} {1}'.format(__name__, cmd), res, False)
        assert res.Succeeded()

if __name__ == '__main__':
    main()
