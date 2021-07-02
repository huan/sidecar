import { TargetProcess } from 'frida'
import {
  log,
}               from '../../config'
import { SidecarBody } from '../../sidecar-body/sidecar-body'

import {
  sidecarMetadata,
}                           from './sidecar-metadata'

import { updateClassName }  from './update-class-name'

function Sidecar (
  targetProcess    : TargetProcess,
  initAgentSource? : string,
) {
  log.verbose('Sidecar', '@Sidecar(%s%s)',
    targetProcess,
    initAgentSource
      ? `, "${initAgentSource.substr(0, 80)}"`
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
      initAgentSource?.substr(0, 80) || '',
      Klass.name,
    )

    // https://stackoverflow.com/a/14486171/1123955
    if (!(Klass.prototype instanceof SidecarBody)) {
      throw new Error('Sidecar: the class decorated by @Sidecar must extends from `SidecarBody`')
    }

    const metadata = sidecarMetadata(Klass)
    void metadata

    // let instance: any = null

    class DecoratedClass extends Klass  {

      static initAgentSource = initAgentSource
      static targetProcess   = targetProcess

      constructor (...args: any[]) {
        super(...args)
        log.verbose(`Sidecar(${this.constructor.name})`, 'constructor(%s)', args.join(','))
      }

    }

    updateClassName(
      DecoratedClass,
      Klass.name,
    )

    return DecoratedClass
  }
}

export { Sidecar }
