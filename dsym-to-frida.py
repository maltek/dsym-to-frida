#!/usr/bin/env python

from __future__ import absolute_import, division, print_function, unicode_literals

import fnmatch
import io
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


def sanitize_name(type, combined=False):
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
    if combined:
        return ".".join(name)
    else:
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


out = io.StringIO()
cmp_out = io.StringIO()
indent = 0
def write(what):
    global indent
    for line in what.split("\n"):
        if what in ('}', '};'):
            indent -= 1
        out.write(indent * 4 * ' ')
        out.write(what)
        out.write("\n")
        if not what.startswith('//'):
            cmp_out.write(what)
            cmp_out.write('\n')
        if what and what[-1] == '{':
            indent += 1


def print_members(target, type, base_offset, mangled_syms):
    deps = set()
    members = type.members
    if type.IsPolymorphicClass() and (not members or members[0].byte_offset == target.GetAddressByteSize()):
        ptr_size = target.GetAddressByteSize()
        write('get _vtable() { return this._ptr.add(%u).readPointer(); }')

    for base in type.bases:
        deps.add(base.type)
        write("// inherited from " + base.type.name)
        deps |= print_members(target, base.type, base.byte_offset + base_offset, mangled_syms)

    assert not type.vbases, "virtual base classes not implemented"

    if type.bases and type.fields:
        write("// own fields")

    for member in type.fields:
        member_type_class = member.type.GetCanonicalType().GetTypeClass()
        is_class_or_struct = member_type_class in (lldb.eTypeClassStruct, lldb.eTypeClassClass)
        is_primitive = member_type_class in (lldb.eTypeClassBuiltin, lldb.eTypeClassEnumeration)

        if is_primitive:
            signed = 'U' if member.type.name.startswith('unsigned ') else 'S'
            bit_mask = 2**member.bitfield_bit_size-1
            if member.type.size <= 4:
                fmt = 'get %s() { return (this._ptr.add(%u).read%c%u()%s)%s; }'
                offset = (' >>> %u' if signed == 'U' else ' >> %u') % (member.bit_offset % 8)
                bit_mask = ' & ' + hex(bit_mask) if bit_mask else ''
            else:
                fmt = 'get %s() { return this._ptr.add(%u).read%c%u()%s%s; }'
                offset = '.shr(%u)' % (member.bit_offset % 8)
                bit_mask = '.and(' + hex(bit_mask) + ')' if bit_mask else ''
            if member.bit_offset % 8 == 0:
                offset = ''
            type_bit_size = member.type.size * 8
            write(fmt % (camel_case(member.name), member.byte_offset + base_offset, signed, type_bit_size,
                         offset, bit_mask))
            if member.bit_offset % 8 == 0 and member.bitfield_bit_size == 0:
                fmt = 'set %s(val) { this._ptr.add(%u).write%c%u(val); }'
                write(fmt % (camel_case(member.name), member.byte_offset + base_offset, signed, type_bit_size))
            else:
                write('set %s(val) {' % camel_case(member.name))
                write('let old, my;')
                def gen_bit_field_write(byte_off, bit_off, bit_size):
                    bit_mask = (2**bit_size - 1) << bit_off
                    bit_mask = hex(bit_mask)

                    write('old = this._ptr.add({0}).readU{1}().and(uint{1}("-1").xor("{2}"));'.format(byte_off, type_bit_size, bit_mask))
                    if type_bit_size > 52:
                        write('my = uint64(val.toString()).shl({0}).and("{1}");'.format(bit_off, bit_mask))
                    else:
                        write('my = (val << {0}) & {1};'.format(bit_off, bit_mask))
                    write('this._ptr.add({0}).writeU{1}(old.or(my));'.format(byte_off, type_bit_size))
                if type_bit_size < member.bit_offset + member.bitfield_bit_size:
                    gen_bit_field_write(member.byte_offset + base_offset, member.bit_offset, type_bit_size - member.bit_offset)
                    gen_bit_field_write(member.byte_offset + base_offset + member.type_size, 0, member.bit_offset + member.bitfield_bit_size - type_bit_size)
                else:
                    gen_bit_field_write(member.byte_offset + base_offset, member.bit_offset, member.bitfield_bit_size)
                write('}')
        elif is_class_or_struct:
            deps.add(member.type)
            fmt = 'get %s() { return new %s(this._ptr.add(%u)); }'
            write(fmt % (camel_case(member.name), sanitize_name(member.type, True), member.byte_offset + base_offset))
        elif member.type.is_pointer or member.type.is_reference:
            pointee = member.type.GetPointeeType()
            if pointee.is_pointer or pointee.is_reference:
                type_fn = ''
                from_high_level = 'val'
            else:
                deps.add(pointee)
                type_fn = 'new {}'.format(sanitize_name(pointee.name, True))
                from_high_level = 'val instanceof {} ? val._ptr : val instanceof NativePointer ? val : throw new Error("got value of wrong type")'.format(sanitize_name(pointee.name, True))
            write('get {0}() {{'.format(camel_case(member.name)))
            write('return {1}(this._ptr.add({0}).readPointer());'.format(member.byte_offset + base_offset, type_fn))
            wrte('}')
            write('set %s(val) {' % camel_case(member.name))
            write('this._ptr.add({0}).writePointer({1});'.format(member.byte_offset + base_offset, from_high_level))
            write('}')

    for i in range(type.GetNumberOfMemberFunctions()):
        func = type.GetMemberFunctionAtIndex(i)
        if func.GetKind() in (lldb.eMemberFunctionKindConstructor,
                              lldb.eMemberFunctionKindDestructor,
                              lldb.eMemberFunctionKindUnknown):
            continue
        fn_name = func.GetName()
        if fn_name.startswith("operator"):
            continue

        # GetMangledName() returns a superfluous \x01 as first byte
        mangled = func.GetMangledName().lstrip('\x01')

        # we won't have private symbols in production
        if mangled not in mangled_syms or not mangled_syms[mangled].external:
            continue

        ret = sanitize_name(func.GetReturnType(), True)
        args = (("arg%d: any" % i) for i in range(func.GetNumberOfArguments()))
        write('%s(%s): %s {' % (func.GetName(), ", ".join(args), ret))

        arg_names = [("arg%d" % i) for i in range(func.GetNumberOfArguments())]
        if func.GetKind() == lldb.eMemberFunctionKindInstanceMethod:
            arg_names = ["this._ptr.add(%d)" % base_offset] + arg_names
        write('return _callFunction("%s", %s);' % (mangled, ", ".join(arg_names)))

        write('}')

    return deps


def print_type(target, type, mangled_syms):
    write("// " + type.name)

    namespace, san_name = sanitize_name(type)
    if namespace:
        write("namespace %s {" % namespace)

    if type.GetTypeClass() == lldb.eTypeClassEnumeration:
        write('export const %s = {' % san_name)
        members = type.GetEnumMembers()
        members = [members.GetTypeEnumMemberAtIndex(i) for i in range(members.GetSize())]
        for member in members:
            write('"{0}": {1},'.format(member.name, member.unsigned))
            write('"{1}": "{0}",'.format(member.name, member.unsigned))
        write("sizeof: {}".format(type.size))
        write('};')
        if namespace:
            write("}")
        return

    write('export class %s {' % san_name)
    write('constructor(_ptr) { this._ptr = _ptr; }')
    deps = print_members(target, type, 0, mangled_syms)

    write('}')
    write('%s.sizeof = %u;' % (san_name, type.size))
    if namespace:
        write("}")
    write("")

    return deps

def find_matches(command):
    args = shlex.split(command) or ['*']
    found = {}
    mangled_syms = {}
    for module in lldb.debugger.GetSelectedTarget().modules:
        for sym in module.symbols:
            if sym.mangled:
                mangled_syms[sym.mangled] = sym
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
    return found, mangled_syms


def list_types(debugger, command, result, dict):
    for name in find_matches(command)[0].keys():
        print(name)

def dump_type(debugger, command, result, dict):
    global cmp_out, out
    generated, mangled_syms = find_matches(command)

    already_printed = {}

    want_output = set(generated.values())
    have_output = set()
    while want_output:
        type = want_output.pop()
        name = sanitize_name(type, True)
        have_output.add(type)
        want_output |= print_type(lldb.target, type, mangled_syms) - have_output
        if name in already_printed:
            if already_printed[name] != cmp_out.getvalue():
                raise Exception("error: multiple types with same mapped TS name but different memory layout!")
        else:
            print(out.getvalue())
            already_printed[name] = cmp_out.getvalue()
        out = io.StringIO()
        cmp_out = io.StringIO()

def __lldb_init_module(debugger, internal_dict):
    for cmd in ['list_types', 'dump_type']:
        res = lldb.SBCommandReturnObject()
        debugger.GetCommandInterpreter().HandleCommand(b'command script add -f {0}.{1} {1}'.format(__name__, cmd), res, False)
        assert res.Succeeded()
