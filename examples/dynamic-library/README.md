# How To Compile a Shared Library

Credit: <https://github.com/node-ffi/node-ffi/tree/master/example/factorial>

To compile `libfactorial.dylib` on OS X:

> See: <https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary>

``` bash
gcc -dynamiclib -undefined suppress -flat_namespace factorial.c -o libfactorial-arm64e.dylib -target arm64e-apple-macos11
gcc -dynamiclib -undefined suppress -flat_namespace factorial.c -o libfactorial-arm64.dylib -target arm64-apple-macos11
gcc -dynamiclib -undefined suppress -flat_namespace factorial.c -o libfactorial-x86_64.dylib -target x86_64-apple-macos10.12
lipo -create -output libfactorial.dylib libfactorial-arm64e.dylib libfactorial-arm64.dylib libfactorial-x86_64.dylib 
```

To compile `libfactorial.so` on Linux/Solaris/etc.:

``` bash
gcc -shared -fpic factorial.c -o libfactorial.so
```

To compile `libfactorial.dll` on Windows (<http://stackoverflow.com/a/2220213>):

``` bash
cl.exe /D_USRDLL /D_WINDLL factorial.c /link /DLL /OUT:libfactorial.dll
```

To run the example:

``` bash
$ ts-node factorial.ts 35
Your output: 6399018521010896896
```
