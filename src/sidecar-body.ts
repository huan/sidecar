import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import {
  log,
}                     from './config'
import {
  Script,
  Session,
}                     from './frida'
import {
  HookEventPayload,
}                     from './schema'

export type HookEventListener = (payload: HookEventPayload) => void

interface SidecarEvents {
  hook: HookEventListener
  error: Error
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>
const SidecarEmitter = EventEmitter as SidecarEmitterType

// let singletonInstance: null | SidecarBody = null

class SidecarBody extends SidecarEmitter {

  /**
   * Frida Script instance, which is in charge of:
   *  1. init agent
   *  2. create call `exports.rpc.*`
   *  3. create hook and emit events with `Intercepter` and `send`
   */
  script?: Script
  session?: Session

  constructor () {
    super()
    log.verbose('SidecarBody', 'constructor()',
      // singletonInstance === null
      //   ? ''
      //   : 'again'
    )

    // /**
    //  * Enforce the class to be singleton.
    //  *
    //  * We enforce the SidecarBody and it's children classes
    //  * can only be instanciated once, because ???
    //  */
    // if (singletonInstance) {
    //   log.verbose('SidecarBody', 'constructor() singleton enforced')
    //   return singletonInstance
    // }
    // singletonInstance = this
  }

  async destroy () {
    try {
      await this.script?.unload()
    } catch (e) {
      this.emit('error', e)
    }

    try {
      await this.session?.detach()
    } catch (e) {
      this.emit('error', e)
    }
  }

}

export { SidecarBody }
