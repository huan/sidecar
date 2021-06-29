import {
  TypeChain,
}                 from '../../frida'
import {
  log,
}               from '../../config'

import { RET_TYPE_SYMBOL } from './constants'

function updateMetadataRetType (
  target      : any,
  propertyKey : string,
  typeChain   : TypeChain,
): void {
  log.verbose('Sidecar', 'updateMetadataRetType(%s, %s, %s)',
    target.name,
    propertyKey,
    JSON.stringify(typeChain)
  )
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
): undefined | TypeChain {
  // Pull the array of parameter names
  const retTypeChain = Reflect.getMetadata(
    RET_TYPE_SYMBOL,
    target,
    propertyKey,
  )
  return retTypeChain
}

export {
  getMetadataRetType,
  updateMetadataRetType,
}
