import {
  log,
}                   from '../../config'

import { updateClassName } from './update-class-name'

interface SidecarOptions {
  /**
   * Frida agent script source code
   */
  initAgent: string,
}

/**
 * number: PID
 * string: File name
 */
type SidecarTarget = number | string

function Sidecar (
  target?  : SidecarTarget,
  options? : SidecarOptions,
) {
  log.verbose('Sidecar', '@Sidecar(%s%s)',
    target || '',
    options
      ? `, "${JSON.stringify(options).substr(0, 80)}"`
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
      target || '',
      options
        ? `, "${JSON.stringify(options).substr(0, 80)}"`
        : '',
      Klass.name,
    )

    // let instance: any = null

    class DecoratedClass extends Klass  {

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
