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
}               from '../frida'
import {
  log,
}               from '../config'

const PARAM_TYPE_SYMBOL = Symbol('parameterType')

function updateParamType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
  typeList       : (NativeType | PointerType)[],
): void {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getOwnMetadata(
    PARAM_TYPE_SYMBOL,
    target,
    propertyKey,
  ) || []
  // Add the current parameter name
  parameterTypeList[parameterIndex] = typeList
  // Update the parameter names
  Reflect.defineMetadata(
    PARAM_TYPE_SYMBOL,
    parameterTypeList,
    target,
    propertyKey,
  )
}

function getParamType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
): (NativeType | PointerType)[] {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getMetadata(
    PARAM_TYPE_SYMBOL,
    target,
    propertyKey,
  ) || []
  return parameterTypeList[parameterIndex]
}

const TypeParameter = (
  nativeType         : NativeType,
  ...pointerTypeList : PointerType[]
) => (
  target         : Object,
  propertyKey    : string | symbol,
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

  updateParamType(
    target,
    propertyKey,
    parameterIndex,
    [nativeType, ...pointerTypeList],
  )
}

export {
  getParamType,
  PARAM_TYPE_SYMBOL,
  TypeParameter,
}
