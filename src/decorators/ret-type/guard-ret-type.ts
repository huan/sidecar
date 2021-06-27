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
  propertyKey : string | symbol,
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
  if (!nativeTypeList.includes(nativeType)) {
    throw new Error(`The ${target.constructor.name}.${String(propertyKey)}(...) decorated by "@RetType(${nativeType}, ...)" does match the design return type "${designRetType?.name}"`)
  }
}

export { guardRetType }
