/**
 * Data Type:
 *  https://en.wikipedia.org/wiki/Data_type
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wizardsoftheweb.pro/typescript-decorators-parameter-decorators/
 */
import {
  NativeType,
  PointerType,
}               from '../../frida'
import {
  log,
}               from '../../config'

import { updateMetadataParamType }  from './metadata-param-type'
import { guardParamType }           from './guard-param-type'

const ParamType = (
  nativeType         : NativeType,
  ...pointerTypeList : PointerType[]
) => (
  target         : Object,
  propertyKey    : string,
  parameterIndex : number,
) => {
  log.verbose('Sidecar',
    'ParamType(%s, %s) => (%s, %s, %s)',
    nativeType,
    pointerTypeList.join(','),
    target.constructor.name,
    propertyKey,
    parameterIndex,
  )

  guardParamType(
    target,
    propertyKey,
    parameterIndex,
    nativeType,
  )

  updateMetadataParamType(
    target,
    propertyKey,
    parameterIndex,
    [nativeType, ...pointerTypeList],
  )
}

export { ParamType }
