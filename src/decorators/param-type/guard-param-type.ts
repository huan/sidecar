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
 * Verify the TypeScript param type is matching the NativeType from `ParamType`
 */
function guardParamType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
  nativeType     : NativeType,
): void {
  const designParamTypeList = Reflect.getMetadata('design:paramtypes', target, propertyKey) as ReflectDesignType[]
  const designParamType = designParamTypeList[parameterIndex]

  log.verbose('Sidecar',
    'guardParamType(%s.%s#%s) designType/nativeType: %s/%s',
    target.constructor.name,
    propertyKey,
    parameterIndex,

    designParamType?.name ?? 'void',
    nativeType,
  )

  const nativeTypeList = toNativeTypeList(designParamType)
  if (!nativeTypeList.includes(nativeType)) {
    throw new Error(`The "${target.constructor.name}.${String(propertyKey)}(#${parameterIndex}) decorated by "@ParamType(${nativeType}, ...)" does match the design type "${designParamType?.name}"`)
  }
}

export { guardParamType }
