A python script for LLDB that (tries to) generate Frida wrapper for C/C++
structures based on debug information - for cases where you have the source of a
program/library, but don't want to manually write lots of wrappers. Note that
the wrappers are platform-specific - they hard-code the exact memory layout
found in the exact debug symbols loaded into LLDB.

You can run it with any C/C++ library or executable for which you have debug
symbols. Use it from the LLDB prompt roughly like this:

```
platform select remote-ios
 
target create -a armv7 /Users/malte/Library/Developer/Xcode/DerivedData/SwiftFridaTests-fdzgqlqfpbydbcbaswxptmrprxwe/Build/Products/Debug-iphoneos/SwiftFridaTests.app/Frameworks/libswiftCore.dylib --symfile /Users/malte/Library/Developer/Toolchains/swift-LOCAL-2019-06-23-a.xctoolchain//usr/lib/swift/iphoneos/libswiftCore.dylib.dSYM
command script import dsym_to_typescript.py
dump_type "swift::TargetMetadata<swift::InProcess>"
```


(Make sure that `/usr/bin/python` is the first `python` in `PATH`, or LLDB will spit out weird Python exceptions.)
