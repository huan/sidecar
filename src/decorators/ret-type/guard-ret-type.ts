import {
  NativeType,
}               from '../../frida'
import {
  log,
}               from '../../config'

import {
  ReflectDesignType,
}                     from '../../schema'
import {
  toNativeTypeList,
}                     from '../../misc'

/**
 * Verify the TypeScript ret type is matching the NativeType from `ParamType`
 */
function guardRetType (
  target      : Object,
  propertyKey : string,
  nativeType  : NativeType,
): void {
  const designRetType = Reflect.getMetadata('design:returntype', target, propertyKey) as ReflectDesignType

  log.verbose('Sidecar',
    'guardRetType(%s.%s) designType/nativeType: %s/%s',
    target.constructor.name,
    propertyKey,

    designRetType?.name ?? 'void',
    nativeType,
  )

  const nativeTypeList = toNativeTypeList(designRetType)
  // console.log(nativeTypeList)

  /**
   * Huan(202106): why `nativeTypeList.length > 0`?
   *  nativeTypeList will be empty for the designType `Promise`
   *  because the TypeScript metadata do not support to get the value inside the `Promise<value>`
   *  so we will not be able to check them.
   */
  if (nativeTypeList.length > 0 && !nativeTypeList.includes(nativeType)) {
    throw new Error(`The ${target.constructor.name}.${String(propertyKey)}() decorated by "@RetType(${nativeType}, ...)" does match the design return type "${designRetType?.name ?? 'void'}"`)
  }
}

export { guardRetType }
