/**
 * Sidecar Bodywork
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */

import {
  log,
}                     from '../config'
import * as frida     from '../frida'
import {
  HookEventPayload,
}                     from '../schema'

import {
  DESTROY_SYMBOL,
  START_SYMBOL,
  STOP_SYMBOL,
  INIT_SYMBOL,

  SCRIPT_DESTROYED_HANDLER_SYMBOL,
  SCRIPT_MESSAGRE_HANDLER_SYMBOL,
  EMIT_PAYLOAD_HANDLER_SYMBOL,
}                                   from './constants'

import { SidecarEmitter } from './sidecar-emitter'

// let singletonInstance: null | SidecarBody = null

class SidecarBody extends SidecarEmitter {

  /**
   * Frida Script instance, which is in charge of:
   *  1. init agent
   *  2. create call `exports.rpc.*`
   *  3. create hook and emit events with `Intercepter` and `send`
   */
  script?: frida.Script
  session?: frida.Session

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

  async [INIT_SYMBOL] () {
    log.verbose('SidecarBody', 'init()')

    const session     = await frida.attach('messaging')
    const agentSource = 'await loadAgentSource()'
    const script      = await session.createScript(agentSource)

    script.message.connect(this[SCRIPT_MESSAGRE_HANDLER_SYMBOL].bind(this))
    script.destroyed.connect(this[SCRIPT_DESTROYED_HANDLER_SYMBOL].bind(this))

    await script.load()

    this.session = session
    this.script = script
  }

  async [START_SYMBOL] () {
    log.verbose('MessagingSidecar', 'stop()')

    if (!this.script) {
      throw new Error('stop() this.script is undefined!')
    }

    await this.script.exports.init()
  }

  async [STOP_SYMBOL] () {
    log.verbose('MessagingSidecar', 'stop()')

    if (this.script) {
      await this.script.unload()
      this.script = undefined
    } else {
      throw new Error('stop() this.script is undefined!')
    }
    if (this.session) {
      await this.session.detach()
      this.session = undefined
    } else {
      throw new Error('stop() this.session is undefined!')
    }
  }

  async [DESTROY_SYMBOL] (): Promise<void> {
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

    this.emit('destroy')
  }

  /**
   * ScriptDestroyedHandler
   */
  private [SCRIPT_DESTROYED_HANDLER_SYMBOL] () {
    log.verbose('MessagingSidecar', 'scriptDestroyedHandler()')
  }

  /**
   * ScriptMessageHandler
   */
  private [SCRIPT_MESSAGRE_HANDLER_SYMBOL] (
    message: frida.Message,
    data: null | Buffer,
  ) {
    log.verbose('MessagingSidecar', 'scriptMessageHandler(%s, %s)', JSON.stringify(message), data)
    switch (message.type) {
      case frida.MessageType.Send:
        log.silly('MessagingSidecar',
          'scriptMessagerHandler() MessageType.Send: %s',
          JSON.stringify(message.payload),
        )

        this[EMIT_PAYLOAD_HANDLER_SYMBOL](
          message.payload as HookEventPayload,
          data,
        )

        break
      case frida.MessageType.Error:
        log.silly('MessagingSidecar',
          'scriptMessagerHandler() MessageType.Error: %s',
          message.stack,
        )
        break

      default:
        throw new Error('MessagingSidecar: scriptMessagerHandler() Error: unknown message type: ' + message)
    }

    if (data) {
      log.silly('MessagingSidecar', 'scriptMessageHandler() data:', data)
    }
  }

  private [EMIT_PAYLOAD_HANDLER_SYMBOL] (
    payload : HookEventPayload,
    data    : null | Buffer,
  ): void {
    log.verbose('MessagingSidecar',
      'emitPayload(%s, %s)',
      payload,
      data,
    )

    this.emit('hook', payload)
  }

}

export { SidecarBody }
