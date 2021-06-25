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

const PARAMETER_TYPE_SYMBOL = Symbol('parameterType')

function updateParameterType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
  typeList       : (NativeType | PointerType)[],
): void {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getOwnMetadata(
    PARAMETER_TYPE_SYMBOL,
    target,
    propertyKey,
  ) || []
  // Add the current parameter name
  parameterTypeList[parameterIndex] = typeList
  // Update the parameter names
  Reflect.defineMetadata(
    PARAMETER_TYPE_SYMBOL,
    parameterTypeList,
    target,
    propertyKey,
  )
}

function getParameterType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
): (NativeType | PointerType)[] {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getMetadata(
    PARAMETER_TYPE_SYMBOL,
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
    'Type<Parameter>(%s, %s) => (%s, %s, %s)',
    nativeType,
    pointerTypeList.join(','),
    target.constructor.name,
    propertyKey,
    parameterIndex,
  )

  updateParameterType(
    target,
    propertyKey,
    parameterIndex,
    [nativeType, ...pointerTypeList],
  )
}

export {
  getParameterType,
  PARAMETER_TYPE_SYMBOL,
  TypeParameter,
}
