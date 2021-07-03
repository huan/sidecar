import { TargetProcess } from 'frida/dist/device'
import {
  log,
}             from '../config'

import {
  SidecarMetadata,
}                       from '../decorators/mod'

import {
  SidecarTarget,
  TypeChain,
}                   from '../frida'

export interface SidecarFunctionDescription {
  name          : string,
  paramTypeList : TypeChain[],
  retType?      : TypeChain,
  target        : SidecarTarget,
}

export interface SidecarView {
  nativeFunctionList : SidecarFunctionDescription[],
  interceptorList    : SidecarFunctionDescription[],
  initAgentSource?   : string,
  targetProcess?     : TargetProcess,
}

function sidecarView (
  metadata: SidecarMetadata,
): SidecarView {
  log.verbose('Sidecar', 'sidecarView(metadata)')
  log.silly('Sidecar', 'sidecarView(%s)', JSON.stringify(metadata))

  const nativeFunctionList: SidecarFunctionDescription[] = []
  const interceptorList   : SidecarFunctionDescription[] = []

  for (const [name, target] of Object.entries(metadata.call)) {
    const functionDescription: SidecarFunctionDescription = {
      name,
      paramTypeList : metadata.paramType[name],
      retType       : metadata.retType[name],
      target,
    }
    nativeFunctionList.push(functionDescription)
  }

  // console.log(metadata.hook)
  for (const [name, target] of Object.entries(metadata.hook)) {
    // console.log(name, 'retType:', metadata.retType[name])
    const functionDescription: SidecarFunctionDescription = {
      name,
      paramTypeList : metadata.paramType[name],
      retType       : metadata.retType[name],
      target,
    }
    interceptorList.push(functionDescription)
  }

  return {
    interceptorList,
    nativeFunctionList,
  }
}

export { sidecarView }
