import {
  log,
}                           from '../../config'
import {
  normalizeFunctionTarget,
}                           from '../../function-target'
import {
  TargetProcess,
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
      ? `, "${JSON.stringify(options).substr(0, 20)}..."`
      : '',
  )

  const interceptorList    : SidecarMetadataFunctionTypeDescription[] = []
  const nativeFunctionList : SidecarMetadataFunctionTypeDescription[] = []

  const propertyList = Object.getOwnPropertyNames(klass.prototype)
  for (const property of propertyList) {
    log.silly('Sidecar', 'buildSidecarMetadata() building "%s.%s"...',
      klass.name,
      property,
    )

    /**
     * 1. Get the metadata of `call` and `hook`
     */
    const callMetadata = getMetadataCall(
      klass.prototype,
      property,
    )
    log.silly('Sidecar', 'buildSidecarMetadata() callMetadata of %s: %s',
      property,
      JSON.stringify(callMetadata),
    )

    const hookMetadata = getMetadataHook(
      klass.prototype,
      property,
    )
    log.silly('Sidecar', 'buildSidecarMetadata() hookMetadata of %s: %s',
      property,
      JSON.stringify(hookMetadata),
    )

    /**
     * 2. Make sure the target exists: either `call` or `hook`
     */
    const target = callMetadata || hookMetadata
    if (!target) {
      log.silly('Sidecar',
        'buildSidecarMetadata() no callMetadata nor hookMetadata of %s: skip this loop',
        property,
      )
      continue
    }
    const targetObj = normalizeFunctionTarget(target)

    /**
     * 3. Get parameter and return types
     */
    const paramTypeMetadata = getMetadataParamType(
      klass.prototype,
      property,
    )
    log.silly('Sidecar', 'buildSidecarMetadata() paramTypeMetadata of %s: %s',
      property,
      JSON.stringify(paramTypeMetadata),
    )

    const retTypeMetadata = getMetadataRetType(
      klass.prototype,
      property,
    )
    log.silly('Sidecar', 'buildSidecarMetadata() retTypeMetadata of %s: %s',
      property,
      JSON.stringify(retTypeMetadata),
    )

    /**
     * Build the function descript and save it
     */
    const functionDescription: SidecarMetadataFunctionTypeDescription = {
      [targetObj.type]: {
        name          : property,
        paramTypeList : paramTypeMetadata,
        retType       : retTypeMetadata,
        target        : targetObj,
      },
    }
    log.silly('Sidecar', 'buildSidecarMetadata() functionDescription of %s: %s',
      property,
      JSON.stringify(functionDescription),
    )

    if (callMetadata) { nativeFunctionList.push(functionDescription)  }
    if (hookMetadata) {    interceptorList.push(functionDescription)  }
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

export { buildSidecarMetadata }
