import { TargetProcess } from 'frida'
import {
  log,
}               from '../../config'

import { SidecarBody } from '../../sidecar-body/sidecar-body'
import { buildSidecarMetadata } from './build-sidecar-metadata'

// import { updateClassName }  from './update-class-name'
// import { SIDECAR_SYMBOL }   from './constants'

import { updateMetadataSidecar } from './metadata-sidecar'

function Sidecar (
  targetProcess    : TargetProcess,
  initAgentScript? : string,
) {
  log.verbose('Sidecar', '@Sidecar(%s%s)',
    targetProcess,
    initAgentScript
      ? `, "${initAgentScript.substr(0, 20)}..."`
      : '',
  )

  return classDecorator

  /**
   * See: https://www.typescriptlang.org/docs/handbook/decorators.html#class-decorators
   */
  function classDecorator <
    T extends {
      new (...args: any[]): {},
    }
  > (
    Klass: T,
  ) {
    log.verbose('Sidecar',
      '@Sidecar(%s%s) classDecorator(%s)',
      targetProcess || '',
      `"${initAgentScript?.substr(0, 20)}..."` || '',
      Klass.name,
    )

    // https://stackoverflow.com/a/14486171/1123955
    if (!(Klass.prototype instanceof SidecarBody)) {
      throw new Error('Sidecar: the class decorated by @Sidecar must extends from `SidecarBody`')
    }

    const meta = buildSidecarMetadata(Klass, {
      initAgentScript,
      targetProcess,
    })
    updateMetadataSidecar(Klass, meta)
  }
}

export { Sidecar }
