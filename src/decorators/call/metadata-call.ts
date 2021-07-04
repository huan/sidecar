import {
  log,
}                 from '../../config'
import {
  FunctionTarget,
}                       from '../../frida'

import { CALL_SYMBOL } from './constants'

function updateMetadataCall (
  target         : Object,
  propertyKey    : string,
  functionTarget : FunctionTarget,
): void {
  log.verbose('Sidecar',
    'updateMetadataCall(%s, %s, %s)',
    target.constructor.name,
    propertyKey,
    typeof functionTarget === 'object' ? JSON.stringify(functionTarget)
      : typeof functionTarget === 'number' ? functionTarget.toString(16)
        : functionTarget,
  )

  // Update the parameter names
  Reflect.defineMetadata(
    CALL_SYMBOL,
    functionTarget,
    target,
    propertyKey,
  )
}

function getMetadataCall (
  target      : Object,
  propertyKey : string,
): undefined | FunctionTarget {
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
