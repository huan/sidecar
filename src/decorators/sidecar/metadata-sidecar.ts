import {
  log,
}               from '../../config'
import {
  SidecarTarget,
  TypeChain,
  TargetProcess,
}                     from '../../frida'

import { SIDECAR_SYMBOL } from './constants'

export interface SidecarMetadataFunctionDescription {
  name          : string,
  paramTypeList : TypeChain[],
  retType?      : TypeChain,
  target        : SidecarTarget,
}

export interface SidecarMetadata {
  nativeFunctionList : SidecarMetadataFunctionDescription[],
  interceptorList    : SidecarMetadataFunctionDescription[],
  initAgentSource?   : string,
  targetProcess?     : TargetProcess,
}

function updateMetadataSidecar (
  target : any,
  view   : SidecarMetadata,
): void {
  log.verbose('Sidecar', 'updateMetadataSidecar(%s, %s)',
    target.name,
    JSON.stringify(view)
  )
  // Update the parameter names
  Reflect.defineMetadata(
    SIDECAR_SYMBOL,
    view,
    target,
  )
}

function getMetadataSidecar (
  target      : Object,
): undefined | SidecarMetadata {
  // Pull the array of parameter names
  const view = Reflect.getMetadata(
    SIDECAR_SYMBOL,
    target,
  )
  return view
}

export {
  getMetadataSidecar,
  updateMetadataSidecar,
}
