import {
  NativeType,
  PointerType,
}                 from '../../frida'
import {
  log,
}               from '../../config'

import { RET_TYPE_SYMBOL } from './constants'

function updateMetadataRetType (
  target      : Object,
  propertyKey : string,
  typeChain   : (NativeType | PointerType)[],
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    RET_TYPE_SYMBOL,
    typeChain,
    target,
    propertyKey,
  )
}

function getMetadataRetType (
  target      : Object,
  propertyKey : string,
): (NativeType | PointerType)[] {
  // Pull the array of parameter names
  const methodTypeList = Reflect.getMetadata(
    RET_TYPE_SYMBOL,
    target,
    propertyKey,
  )
  if (!Array.isArray(methodTypeList) || methodTypeList.length <= 0) {
    log.error('Sidecar', 'getRetType() can not get metadata.')
    log.error('Stack: %s', new Error().stack)
  }
  return methodTypeList
}

export {
  getMetadataRetType,
  updateMetadataRetType,
}
