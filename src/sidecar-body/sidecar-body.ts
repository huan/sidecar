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

export enum SpawnMode {
  Default = 0,
  Always  = 1,
  Never   = 2,
}

export interface SidecarBodyOptions {
  initAgentSource : string,
  spawnMode       : SpawnMode,
  targetProcess   : frida.TargetProcess,
}

class SidecarBody extends SidecarEmitter {

  /**
   * Frida Script instance, which is in charge of:
   *  1. init agent
   *  2. create call `exports.rpc.*`
   *  3. create hook and emit events with `Intercepter` and `send`
   */
  script?:  frida.Script
  session?: frida.Session

  /**
   * Constructor options:
   */
  initAgentSource : string
  spawnMode       : SpawnMode
  targetProcess   : frida.TargetProcess

  constructor (
    options?: SidecarBodyOptions,
  ) {
    super()
    log.verbose('SidecarBody', 'constructor(%s)',
      options
        ? `"${JSON.stringify(options)}`
        : '',
    )

    const Klass = this.constructor as any as {
      initAgentSource : string,
      targetProcess?  : frida.TargetProcess
    }

    this.initAgentSource = options?.initAgentSource || Klass.initAgentSource || ''
    this.spawnMode       = options?.spawnMode       || SpawnMode.Default
    this.targetProcess   = options?.targetProcess    || Klass.targetProcess || ''

    if (!this.targetProcess) {
      throw new Error('Sidecar must specify the "targetProcess" either by the "@Sidecar" decorator, or the "constructor()" function.')
    }
  }

  async [INIT_SYMBOL] () {
    log.verbose('SidecarBody', '[INIT_SYMBOL]()')

    let pid: number
    let session : frida.Session

    switch (this.spawnMode) {
      /**
       * Default: attach first, if failed, then try spawn.
       */
      case SpawnMode.Default:
        try {
          session = await frida.attach(this.targetProcess)
        } catch (e) {
          log.silly('SidecarBody',
            '[INIT_SYMBOL]() SpawnMode.Default attach(%s) failed. trying spawn...',
            this.targetProcess,
          )
          if (typeof this.targetProcess === 'number') {
            throw new Error('Sidecar: can not spawn a number "targetProcess": ' + this.targetProcess)
          }
          pid = await frida.spawn(this.targetProcess)
          session = await frida.attach(pid)
        }
        break

      case SpawnMode.Always:
        if (typeof this.targetProcess === 'number') {
          throw new Error(`Sidecar: "targetProcess" must be program when using SpawnMode.Always. We got: ${this.spawnMode}`)
        }
        pid = await frida.spawn(this.targetProcess)
        session = await frida.attach(pid)
        break

      case SpawnMode.Never:
        session = await frida.attach(this.targetProcess)
        break

      default:
        throw new Error('Sidecar: unknown SpawnMode: ' + this.spawnMode)
    }

    const script = await session.createScript(this.initAgentSource)

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
      throw new Error('[ATTACH_SYMBOL]() this.script is undefined!')
    }

    if ('init' in this.script.exports) {
      await this.script.exports.init()
    } else {
      log.warn('SidecarBody', '[ATTACH_SYMBOL]() "init" not found in "script.exports"')
    }

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
