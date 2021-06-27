import {
  NativeType,
  PointerType,
}                 from '../../frida'

import { PARAM_TYPE_SYMBOL } from './constants'

function updateParamType (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
  typeChain      : [NativeType, ...PointerType[]],
): void {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getOwnMetadata(
    PARAM_TYPE_SYMBOL,
    target,
    propertyKey,
  ) || []
  // Add the current parameter name
  parameterTypeList[parameterIndex] = typeChain
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
): [NativeType, ...PointerType[]] {
  // Pull the array of parameter names
  const parameterTypeList = Reflect.getMetadata(
    PARAM_TYPE_SYMBOL,
    target,
    propertyKey,
  ) || []
  return parameterTypeList[parameterIndex]
}

export {
  getParamType,
  updateParamType,
}
