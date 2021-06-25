/**
 * Sidecar frida
 *
 * Huan <zixia@zixia.net>, June 25, 2021
 *  https://github.com/huan/sidecar
 */
export * from 'frida'
export {
  ScriptMessageHandler,
  ScriptDestroyedHandler,
}                           from 'frida/dist/script'

/**
 * Frida Target
 *
 *  number:
 *    - 0x1234
 *
 *  string:
 *    - lib: 'open'
 *    - ObjC: '- connection:didReceiveData:'
 */
export type FridaTarget = number
                        | string

/**
 * NativeFunction
 *  https://frida.re/docs/javascript-api/#nativefunction
 */
export type NativeType =  'void'
                        | 'pointer'
                        | 'int'
                        | 'uint'
                        | 'long'
                        | 'ulong'
                        | 'char'
                        | 'uchar'
                        | 'size_t'
                        | 'ssize_t'
                        | 'float'
                        | 'double'
                        | 'int8'
                        | 'uint8'
                        | 'int16'
                        | 'uint16'
                        | 'int32'
                        | 'uint32'
                        | 'int64'
                        | 'uint64'
                        | 'bool'

/**
 * NativePointer
 *  https://frida.re/docs/javascript-api/#nativepointer
 */
export type PointerType = 'Pointer'
                        | 'S8'
                        | 'U8'
                        | 'S16'
                        | 'U16'
                        | 'S32'
                        | 'U32'
                        | 'Short'
                        | 'UShort'
                        | 'Int'
                        | 'UInt'
                        | 'Float'
                        | 'Double'
                        | 'S64'
                        | 'U64'
                        | 'Long'
                        | 'ULong'
                        | 'ByteArray'
                        | 'CString'
                        | 'Utf8String'
                        | 'Utf16String'
                        | 'AnsiString'

// export type DataType = [NativeType, ...(undefined | PointerType)[]]
