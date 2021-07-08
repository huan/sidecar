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
  propertyKey    : string,
  parameterIndex : number,
  nativeType     : NativeType,
): void {
  const designParamTypeList = Reflect.getMetadata('design:paramtypes', target, propertyKey) as ReflectDesignType[]
  const designParamType = designParamTypeList[parameterIndex]

  log.verbose('Sidecar',
    'guardParamType(%s, %s, %s) %s.%s(args[%s]) designType/nativeType: %s/%s',
    target.constructor.name,
    propertyKey,
    parameterIndex,

    target.constructor.name,
    propertyKey,
    parameterIndex,

    designParamType?.name ?? 'void',
    nativeType,
  )

  // Huan(202107) add check for PointerType
  const nativeTypeList = toNativeTypeList(designParamType)
  if (!nativeTypeList.includes(nativeType)) {
    throw new Error([
      `The "${target.constructor.name}.${String(propertyKey)}(args[${parameterIndex}])`,
      `decorated by "@ParamType(${nativeType}, ...)"`,
      `does match the design type "${designParamType?.name}"`,
    ].join('\n'))
  }
}

export { guardParamType }
