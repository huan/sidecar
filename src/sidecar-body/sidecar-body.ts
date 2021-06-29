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
  ATTACH_SYMBOL,
  DETACH_SYMBOL,
  INIT_SYMBOL,

  SCRIPT_DESTROYED_HANDLER_SYMBOL,
  SCRIPT_MESSAGRE_HANDLER_SYMBOL,
}                                   from './constants'

import { SidecarEmitter } from './sidecar-emitter'

class SidecarBody extends SidecarEmitter {

  /**
   * Frida Script instance, which is in charge of:
   *  1. init agent
   *  2. create call `exports.rpc.*`
   *  3. create hook and emit events with `Intercepter` and `send`
   */
  script?:  frida.Script
  session?: frida.Session

  constructor () {
    super()
    log.verbose('SidecarBody', 'constructor()',
      // singletonInstance === null
      //   ? ''
      //   : 'again'
    )
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

    this.emit('inited')
  }

  async [ATTACH_SYMBOL] () {
    log.verbose('SidecarBody', '[ATTACH_SYMBOL]()')

    if (!this.script) {
      throw new Error('stop() this.script is undefined!')
    }

    await this.script.exports.init()

    this.emit('attached')
  }

  async [DETACH_SYMBOL] () {
    log.verbose('SidecarBody', '[DETACH_SYMBOL]()')

    if (this.script) {
      await this.script.unload()
      this.script = undefined
    } else {
      log.error('SidecarBody', '[DETACH_SYMBOL]() this.script is undefined!')
    }

    if (this.session) {
      await this.session.detach()
      this.session = undefined
    } else {
      log.error('SidecarBody', '[DETACH_SYMBOL]() this.session is undefined!')
    }

    this.emit('detached')
  }

  /**
   * ScriptDestroyedHandler
   */
  private [SCRIPT_DESTROYED_HANDLER_SYMBOL] () {
    log.verbose('SidecarBody', '[SCRIPT_DESTROYED_HANDLER_SYMBOL]()')

    if (this.script || this.session) {
      this[DETACH_SYMBOL]()
        .catch(e => {
          log.error('SidecarBody', '[SCRIPT_DESTROYED_HANDLER_SYMBOL]() rejection: %s\n%s',
            e && e.message,
            e && e.stack,
          )
        })
    }
  }

  /**
   * ScriptMessageHandler
   */
  private [SCRIPT_MESSAGRE_HANDLER_SYMBOL] (
    message: frida.Message,
    data: null | Buffer,
  ) {
    log.verbose('SidecarBody', '[SCRIPT_MESSAGRE_HANDLER_SYMBOL](%s, %s)', JSON.stringify(message), data)
    switch (message.type) {
      case frida.MessageType.Send:
        log.silly('SidecarBody',
          '[SCRIPT_MESSAGRE_HANDLER_SYMBOL]() MessageType.Send: %s',
          JSON.stringify(message.payload),
        )
        {
          const payload: HookEventPayload = {
            ...message.payload,
            data,
          }
          this.emit('hook', payload)
        }

        break
      case frida.MessageType.Error:
        log.error('SidecarBody',
          '[SCRIPT_MESSAGRE_HANDLER_SYMBOL]() MessageType.Error: %s',
          message.stack,
        )
        {
          const e = new Error(message.description)
          e.stack = e.stack + '\n\n' + message.stack
          this.emit('error', e)
        }
        break

      default:
        throw new Error('MessagingSidecar: [SCRIPT_MESSAGRE_HANDLER_SYMBOL]() Error: unknown message type: ' + message)
    }

    if (data) {
      log.silly('SidecarBody', '[SCRIPT_MESSAGRE_HANDLER_SYMBOL]() data:', data)
    }
  }

}

export { SidecarBody }
