import { TargetProcess } from 'frida/dist/device'
import {
  log,
}                   from '../../config'
import {
  FunctionTarget,
  TypeChain,
  normalizeFunctionTarget,
}                           from '../../frida'

import { getMetadataCall }        from '../call/metadata-call'
import { getMetadataHook }        from '../hook/hook'
import { getMetadataParamType }   from '../param-type/metadata-param-type'
import { getMetadataRetType }     from '../ret-type/metadata-ret-type'

import {
  SidecarMetadata,
  SidecarMetadataFunctionTypeDescription,
}                                       from './metadata-sidecar'

interface BuildSidecarMetadataOptions {
  initAgentSource? : string,
  targetProcess?   : TargetProcess,
}

function buildSidecarMetadata <T extends {
  new (...args: any[]): {},
}> (
  klass   : T,
  options : BuildSidecarMetadataOptions = {},
): SidecarMetadata {
  log.verbose('Sidecar', 'buildSidecarMetadata(%s%s)',
    klass.name,
    options
      ? `, "${JSON.stringify(options)}"`
      : '',
  )

  const config = buildSidecarConfig(klass)

  const interceptorList    : SidecarMetadataFunctionTypeDescription[] = []
  const nativeFunctionList : SidecarMetadataFunctionTypeDescription[] = []

  /**
   * Process Call Config
   */
  for (const [name, functionTarget] of Object.entries(config.call)) {
    const wrappedTarget = normalizeFunctionTarget(functionTarget)
    const functionDescription: SidecarMetadataFunctionTypeDescription = {
      [wrappedTarget.type]: {
        name,
        paramTypeList : config.paramType[name],
        retType       : config.retType[name],
        target        : wrappedTarget.target,
        type          : wrappedTarget.type,
      },
    }
    nativeFunctionList.push(functionDescription)
  }

  /**
   * Process Hook Config
   */
  // console.log(metadata.hook)
  for (const [name, functionTarget] of Object.entries(config.hook)) {
    // console.log(name, 'retType:', metadata.retType[name])
    const wrappedTarget = normalizeFunctionTarget(functionTarget)
    const functionDescription: SidecarMetadataFunctionTypeDescription = {
      [wrappedTarget.type]: {
        name,
        paramTypeList : config.paramType[name],
        retType       : config.retType[name],
        target        : wrappedTarget.target,
        type          : wrappedTarget.type,
      },
    }
    interceptorList.push(functionDescription)
  }

  const {
    initAgentSource,
    targetProcess,
  }                   = options

  return {
    initAgentSource,
    interceptorList,
    nativeFunctionList,
    targetProcess,
  }
}

interface SidecarConfig {
  call             : { [k: string]: FunctionTarget }
  hook             : { [k: string]: FunctionTarget }
  paramType        : { [k: string]: TypeChain[]  }
  retType          : { [k: string]: TypeChain    }
}

function buildSidecarConfig <T extends {
  new (...args: any[]): {},
}> (
  klass   : T,
): SidecarConfig {
  log.verbose('Sidecar', 'buildSidecarConfig(%s)', klass.name)

  const callMetadataMap:      SidecarConfig['call']      = {}
  const hookMetadataMap:      SidecarConfig['hook']      = {}
  const paramTypeMetadataMap: SidecarConfig['paramType'] = {}
  const retTypeMetadataMap:   SidecarConfig['retType']   = {}

  const propertyList = Object.getOwnPropertyNames(klass.prototype)
  for (const property of propertyList) {
    log.silly('Sidecar', 'buildSidecarConfig() inspecting "%s.%s"...',
      klass.name,
      property,
    )

    /**
     * Call Metadata
     */
    const callMetadata = getMetadataCall(
      klass.prototype,
      property,
    )
    if (callMetadata) {
      log.silly('Sidecar', 'buildSidecarConfig() callMetadata: %s',
        typeof callMetadata === 'object' ? JSON.stringify(callMetadata)
          : typeof callMetadata === 'number' ? callMetadata.toString(16)
            : callMetadata,
      )
      callMetadataMap[property] = callMetadata
    }

    /**
     * Hook Metadata
     */
    const hookMetadata = getMetadataHook(
      klass.prototype,
      property,
    )
    if (hookMetadata) {
      log.silly('Sidecar', 'buildSidecarConfig() hookMetadata: %s',
        typeof hookMetadata === 'object' ? JSON.stringify(hookMetadata)
          : typeof hookMetadata === 'number' ? hookMetadata.toString(16)
            : hookMetadata,
      )
      hookMetadataMap[property] = hookMetadata
    }

    /**
     * Param Type Metadata
     */
    const paramTypeMetadata = getMetadataParamType(
      klass.prototype,
      property,
    )
    if (paramTypeMetadata) {
      log.silly('Sidecar', 'buildSidecarConfig() paramTypeMetadata: %s',
        JSON.stringify(paramTypeMetadata),
      )
      paramTypeMetadataMap[property] = paramTypeMetadata
    }

    /**
     * Hook Metadata
     */
    const retTypeMetadata = getMetadataRetType(
      klass.prototype,
      property,
    )
    if (retTypeMetadata) {
      log.silly('Sidecar', 'buildSidecarConfig() retTypeMetadata: %s',
        JSON.stringify(retTypeMetadata),
      )
      retTypeMetadataMap[property] = retTypeMetadata
    }
  }

  log.silly('Sidebar', 'buildSidecarConfig() callProperties: %s', JSON.stringify(callMetadataMap))
  log.silly('Sidebar', 'buildSidecarConfig() hookProperties: %s', JSON.stringify(hookMetadataMap))

  const config = {
    call      : callMetadataMap,
    hook      : hookMetadataMap,
    paramType : paramTypeMetadataMap,
    retType   : retTypeMetadataMap,
  }
  // console.log('meta', JSON.stringify(meta, null, 2))

  return config
}

export { buildSidecarMetadata }
