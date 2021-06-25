import path from 'path'

import {
  log,
}                   from '../config'
import { AgentMother }  from '../agent-mother'

import { FridaTarget } from '../frida'

interface SidecarOptions {
  /**
   * Frida agent script source code
   */
  initAgent: string,
}

function Sidecar (
  target?: FridaTarget,
  options?: SidecarOptions,
) {
  log.verbose('Sidecar', '(%s%s)',
    target || '',
    options
      ? `'${JSON.stringify(options).substr(0, 80)}'`
      : ''
  )

  const agentMother = AgentMother.instance()

  /**
   * Freeze the current library settings,
   * and save the libIndex for finalizing.
   */
  const agentId = agentMother.getCurrentAgentId()
  agentMother.graduateCurrentAgent()

  return getClassDecorator(agentId, target, options)
}

function getClassDecorator (
  agentId: number,
  target?: FridaTarget,
  options?: SidecarOptions,
) {
  log.verbose('Sidecar',
    'getClassDecorator(agentId=%s)',
    agentId,
  )

  /**
   * See: https://www.typescriptlang.org/docs/handbook/decorators.html#class-decorators
   */
  return function classDecorator <
    T extends {
      new (...args: any[]): {},
    }
  > (
    constructor:T,
  ) {
    let instance: any = null

    return class extends constructor {

      constructor (...args: any[]) {
        super(...args)

        if (instance) {
          log.verbose(`Sidecar(${this.constructor.name})`, 'constructor() singleton')
          return instance // return the singleton instance after the first initiation.
        } else {
          /**
           * Constructor Tasks
           */
          log.verbose(`Sidecar(${this.constructor.name})`, 'constructor(%s)', args.join(','))
          instance = this

          backendFinalize(
            args,
            agentId,
            target,
            options,
          )
          // no need to return at the first instantiation.
        }

      }

    }
  }
}

/**
 * Finalize the library backend by file from libraryFile or args.
 */
function backendFinalize (
  args: any[],
  agentId: number,
  target?: TargetType,
  options?: SidecarOptions,
): void {
  log.verbose('Sidecar', 'backendFinalize(%s, %s, %s)', agentId, libraryFile, JSON.stringify(args))

  /**
   * The libraryFile in constructor(libraryFile) has high priority
   */
  if (typeof args[0] !== 'undefined') {
    if (typeof args[0] !== 'string') {
      throw new Error('constructor(arg1): the arg1 must be the library path!')
    }
    libraryFile = args[0]
  }

  if (!libraryFile) {
    throw new Error('ffi-adapter: we must specify library file in @LIBRARY(libFile) or in the first arg of constructor(libFile)!')
  }

  backend.finalize(
    agentId,
    path.resolve(libraryFile),
  )
}

export { Sidecar }
