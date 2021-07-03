import {
  log,
}                   from '../../config'
import {
  SidecarTarget,
  TypeChain,
}                   from '../../frida'
import { SidecarBody } from '../../sidecar-body/sidecar-body'

import { getMetadataCall }        from '../call/metadata-call'
import { getMetadataHook }        from '../hook/hook'
import { getMetadataParamType }   from '../param-type/metadata-param-type'
import { getMetadataRetType }     from '../ret-type/metadata-ret-type'

export interface SidecarMetadata {
  call      : { [k: string]: SidecarTarget }
  hook      : { [k: string]: SidecarTarget }
  paramType : { [k: string]: TypeChain[]  }
  retType   : { [k: string]: TypeChain    }
}

function sidecarMetadata <T extends {
  new (...args: any[]): {},
}> (
  klass: T,
): SidecarMetadata {
  log.verbose('Sidecar', 'sidecarMetadata(%s)', klass.name)

  let directChildClass = klass
  if (Object.getPrototypeOf(klass) !== SidecarBody) {
    log.silly('Sidecar', 'sidecarMetadata() klass is not direct child of SidecarBody, unwraping...')

    directChildClass = Object.getPrototypeOf(klass)
    if (Object.getPrototypeOf(directChildClass) !== SidecarBody) {
      throw new Error('Sidecar: sidecarMetadata() klass must be child of SidecarBody!')
    }
    log.silly('Sidecar', 'sidecarMetadata() klass -> directChildClass is direct child of SidecarBody now')
  }

  const callMetadataMap:      SidecarMetadata['call']      = {}
  const hookMetadataMap:      SidecarMetadata['hook']      = {}
  const paramTypeMetadataMap: SidecarMetadata['paramType'] = {}
  const retTypeMetadataMap:   SidecarMetadata['retType']   = {}

  const propertyList = Object.getOwnPropertyNames(directChildClass.prototype)
  for (const property of propertyList) {

    log.silly('Sidecar', 'sidecarMetadata() inspecting "%s.%s"...',
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
      log.silly('Sidecar', 'sidecarMetadata() callMetadata: %s',
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
      log.silly('Sidecar', 'sidecarMetadata() hookMetadata: %s',
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
      log.silly('Sidecar', 'sidecarMetadata() paramTypeMetadata: %s',
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
      log.silly('Sidecar', 'sidecarMetadata() retTypeMetadata: %s',
        JSON.stringify(retTypeMetadata),
      )
      retTypeMetadataMap[property] = retTypeMetadata
    }
  }

  log.silly('Sidebar', 'sidecarMetadata() callProperties: %s', JSON.stringify(callMetadataMap))
  log.silly('Sidebar', 'sidecarMetadata() hookProperties: %s', JSON.stringify(hookMetadataMap))

  const meta = {
    call      : callMetadataMap,
    hook      : hookMetadataMap,
    paramType : paramTypeMetadataMap,
    retType   : retTypeMetadataMap,
  }
  // console.log('meta', JSON.stringify(meta, null, 2))

  return meta
}

export { sidecarMetadata }
