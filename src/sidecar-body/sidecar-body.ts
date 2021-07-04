/**
 * Sidecar Bodywork
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import path from 'path'

import { buildAgentSource }   from '../agent/build-agent-source'
import { getMetadataSidecar } from '../decorators/sidecar/metadata-sidecar'

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
  initAgentSource? : string,
  spawnMode?       : SpawnMode,
  targetProcess?   : frida.TargetProcess,
}

class SidecarBody extends SidecarEmitter {

  /**
   * Frida Script instance, which is in charge of:
   *  1. init agent
   *  2. create call `exports.rpc.*`
   *  3. create hook and emit events with `Intercepter` and `send`
   */
  script?      : frida.Script
  session?     : frida.Session
  agentSource? : string

  /**
   * Constructor options:
   */
  initAgentSource? : string
  spawnMode        : SpawnMode
  targetProcess?   : frida.TargetProcess

  constructor (
    options?: SidecarBodyOptions,
  ) {
    super()
    log.verbose('SidecarBody', 'constructor(%s)',
      options
        ? `"${JSON.stringify(options)}`
        : '',
    )

    this.initAgentSource  = options?.initAgentSource
    this.spawnMode        = options?.spawnMode || SpawnMode.Default
    this.targetProcess    = options?.targetProcess
  }

  protected async [INIT_SYMBOL] () {
    log.verbose('SidecarBody', '[INIT_SYMBOL]()')

    const Klass = this.constructor as any
    const metadata  = getMetadataSidecar(Klass)

    if (!metadata) {
      throw new Error([
        'Sidecar:',
        'SidcarBody[INIT_SYMBOL]() getMetadataSidecar return undefined',
      ].join('\n'))
    }

    /**
     * 1. initAgentSource
     */
    if (this.initAgentSource) {
      log.silly('SidecarBody', '[INIT_SYMBOL]() initAgentSource has been specified from constructor args')
    } else {
      log.silly('SidecarBody', '[INIT_SYMBOL]() load initAgentSource from metadata')
      this.initAgentSource = metadata.initAgentSource || ''
    }

    /**
     * 2. targetProcess
     */
    if (this.targetProcess) {
      log.silly('SidecarBody', '[INIT_SYMBOL]() targetProgress has been specified from constructor args')
    } else {
      if (!metadata.targetProcess) {
        throw new Error([
          'Sidecar must specify the "targetProcess"',
          'either by the "@Sidecar" decorator,',
          'or in the "constructor()" parameters.',
        ].join('\n'))
      }
      log.silly('SidecarBody', '[INIT_SYMBOL]() load targetProgress from metadata')
      this.targetProcess = metadata.targetProcess
    }

    /**
     * 3. agentSource
     */
    this.agentSource = await buildAgentSource({
      ...metadata,
      initAgentSource: this.initAgentSource || metadata.initAgentSource,
    })

    this.emit('inited')
  }

  async [ATTACH_SYMBOL] () {
    log.verbose('SidecarBody', '[ATTACH_SYMBOL]()')

    if (!this.agentSource) {
      await this[INIT_SYMBOL]()
    }

    if (!(
      this.agentSource && this.targetProcess
    )) {
      throw new Error([
        'Sidecar:',
        'agentSource or targetProcess not found.',
      ].join('\n'))
    }

    const moduleName = typeof this.targetProcess === 'number'
      ? this.targetProcess
      : path.basename(this.targetProcess)

    const resumeCallbackList = []

    let pid: number
    let session : frida.Session

    switch (this.spawnMode) {
      /**
       * Default: attach first, if failed, then try spawn.
       */
      case SpawnMode.Default:
        try {
          session = await frida.attach(moduleName)
        } catch (e) {
          log.silly('SidecarBody',
            '[ATTACH_SYMBOL]() SpawnMode.Default attach(%s) failed. trying spawn...',
            moduleName,
          )
          if (typeof this.targetProcess === 'number') {
            this.emit('error', e)
            return
          }

          try {
            pid = await frida.spawn(this.targetProcess)
            log.silly('SidecarBody',
              '[ATTACH_SYMBOL]() spawn(%s) succeed: pid = %s',
              this.targetProcess,
              pid,
            )
            session = await frida.attach(pid)
          } catch (e) {
            log.error('SidecarBody',
              '[ATTACH_SYMBOL]() spawn(%s) failed: %s\n%s',
              e && e.message,
              e && e.stack,
            )
            this.emit('error', e)
            return
          }

          resumeCallbackList.push(() => frida.resume(pid))
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

    const script = await session.createScript(this.agentSource)

    script.message.connect(this[SCRIPT_MESSAGRE_HANDLER_SYMBOL].bind(this))
    script.destroyed.connect(this[SCRIPT_DESTROYED_HANDLER_SYMBOL].bind(this))

    await script.load()

    if (script.exports && script.exports.init) {
      // Huan(202106)
      // FIXME: do we need to call init() here?
      // It seems that frida will call init() automatically in CLI
      await script.exports.init()
    } else {
      log.warn('SidecarBody', '[ATTACH_SYMBOL]() "init" not found in "script.exports"')
    }

    this.session = session
    this.script  = script

    this.emit('attached')

    /**
     * Delay resume after `emit`
     */
    while (true) {
      const fn = resumeCallbackList.pop()
      if (!fn) {
        break
      }
      await fn()
    }
  }

  async [DETACH_SYMBOL] () {
    log.verbose('SidecarBody', '[DETACH_SYMBOL]()')

    if (this.script) {
      const script = this.script
      this.script = undefined
      try {
        await script.unload()
      } catch (e) {
        log.error('SidecarBody',
          '[DETACH_SYMBOL]() script.unload() rejection: %s\n%s',
          e && e.message,
          e && e.stack,
        )
        this.emit('error', e)
      }
    } else {
      log.silly('SidecarBody', '[DETACH_SYMBOL]() this.script is undefined')
    }

    if (this.session) {
      const session = this.session
      this.session = undefined
      try {
        await session.detach()
      } catch (e) {
        log.error('SidecarBody',
          '[DETACH_SYMBOL]() session.detach() rejection: %s\n%s',
          e && e.message,
          e && e.stack,
        )
        this.emit('error', e)
      }
    } else {
      log.silly('SidecarBody', '[DETACH_SYMBOL]() this.session is undefined')
    }

    this.emit('detached')
  }

  /**
   * ScriptDestroyedHandler
   */
  private async [SCRIPT_DESTROYED_HANDLER_SYMBOL] (): Promise<void> {
    log.verbose('SidecarBody', '[SCRIPT_DESTROYED_HANDLER_SYMBOL]()')

    /**
     * Huan(202106): this function will be called
     *  when we call `script.unload()` from `[DETATCH_SYMBOL]()`
     *
     *  If that, the `this.script` should has already be set to undefined
     *  and we need not to call [DETATCH_SYMBOL]() again.
     */
    if (this.script) {
      try {
        await this[DETACH_SYMBOL]()
      } catch (e) {
        this.emit('error', e)
      }
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
