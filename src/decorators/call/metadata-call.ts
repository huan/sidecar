import {
  FridaTarget,
  LabelTarget,
}                       from '../../frida'

import { CALL_SYMBOL } from './constants'

function updateMetadataCall (
  target      : Object,
  propertyKey : string,
  fridaTarget : FridaTarget | LabelTarget,
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    CALL_SYMBOL,
    fridaTarget,
    target,
    propertyKey,
  )
}

function getMetadataCall (
  target      : Object,
  propertyKey : string,
): undefined | FridaTarget | LabelTarget {
  // Pull the array of parameter names
  const fridaTarget = Reflect.getMetadata(
    CALL_SYMBOL,
    target,
    propertyKey,
  )
  return fridaTarget
}

export {
  updateMetadataCall,
  getMetadataCall,
}
