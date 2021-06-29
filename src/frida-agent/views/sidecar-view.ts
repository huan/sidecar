import {
  log,
}             from '../../config'

import {
  SidecarMetadata,
}                       from '../../decorators/mod'

import {
  SidecarTarget,
  TypeChain,
}                   from '../../frida'

export interface AgentFunction {
  name          : string,
  paramTypeList : TypeChain[],
  retType?      : TypeChain,
  target        : SidecarTarget,
}

export interface SidecarView {
  nativeFunctionList : AgentFunction[],
  interceptorList    : AgentFunction[],
}

function sidecarView (
  metadata: SidecarMetadata,
): SidecarView {
  log.verbose('Sidecar', 'sidecarView(metadata)')
  log.silly('Sidecar', 'sidecarView(%s)', JSON.stringify(metadata, null, 2))

  const nativeFunctionList: AgentFunction[] = []
  const interceptorList   : AgentFunction[] = []

  for (const [name, target] of Object.entries(metadata.call)) {
    const agentFunction: AgentFunction = {
      name,
      paramTypeList : metadata.paramType[name],
      retType       : metadata.retType[name],
      target,
    }
    nativeFunctionList.push(agentFunction)
  }

  for (const [name, target] of Object.entries(metadata.hook)) {
    const agentFunction: AgentFunction = {
      name,
      paramTypeList : metadata.paramType[name],
      retType       : metadata.retType[name],
      target,
    }
    interceptorList.push(agentFunction)
  }

  return {
    interceptorList,
    nativeFunctionList,
  }
}

export { sidecarView }
