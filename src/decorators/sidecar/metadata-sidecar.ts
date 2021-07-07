import {
  log,
}               from '../../config'
import {
  TypeChain,
  TargetProcess,
}                       from '../../frida'
import {
  TargetPayloadObj,
  FunctionTargetType,
}                     from '../../function-target'

import { SIDECAR_SYMBOL } from './constants'

export interface SidecarMetadataFunctionDescription {
  name          : string
  paramTypeList : TypeChain[]
  retType?      : TypeChain
  target        : TargetPayloadObj,
}

export type SidecarMetadataFunctionTypeDescription = {
  [type in FunctionTargetType]?: SidecarMetadataFunctionDescription
}

export interface SidecarMetadata {
  nativeFunctionList : SidecarMetadataFunctionTypeDescription[],
  interceptorList    : SidecarMetadataFunctionTypeDescription[],
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
