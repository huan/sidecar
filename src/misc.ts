// import ref from 'ref'

import {
  NativeType,
}                           from './frida'
import {
  ReflectDesignType,
}                           from './schema'

const designTypeMap = new Map<ReflectDesignType, NativeType[]>()
  .set(undefined, ['void'])
  .set(String, ['pointer'])
  .set(Number, [
    'int',
    'uint',
    'long',
    'ulong',
    'char',
    'uchar',
    'size_t',
    'ssize_t',
    'float',
    'double',
    'int8',
    'uint8',
    'int16',
    'uint16',
    'int32',
    'uint32',
    'int64',
    'uint64',
  ])
  .set(Buffer, ['pointer'])
  .set(Boolean, ['bool'])

function toNativeType (
  designType: ReflectDesignType,
): NativeType[] {
  if (!designTypeMap.has(designType)) {
    throw new Error(`Unsupported designType: ${typeof designType} ${designType && designType.name} ${designType}`)
  }

  const nativeTypeList = designTypeMap.get(designType)
  if (!nativeTypeList || nativeTypeList.length <= 0) {
    throw new Error('nativeType can not found from designTypeMap[' + designType + ']')
  }

  return nativeTypeList
}

/**
 * Huan(202106):
    > class Test {}
    undefined
    > typeof Test
    'function'
    > const t = new Test()
    undefined
    > typeof t
    'object'
 */
function isInstance (target: any): boolean {
  switch (typeof target) {
    case 'function':  // Class
      if (target.name) {
        return false
      }
      break
    case 'object':  // instance
      if (!target.name) {
        return true
      }
      break
  }
  throw new Error('FIXME: Unknown state for target.')
}

export {
  toNativeType,
  isInstance,
}
