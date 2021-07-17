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
  ATTACH_SYMBOL,
  DETACH_SYMBOL,
  INIT_SYMBOL,

  SCRIPT_DESTROYED_HANDLER_SYMBOL,
  SCRIPT_MESSAGRE_HANDLER_SYMBOL,

  LOG_EVENT_HANDLER,
  HOOK_EVENT_HANDLER,
}                                   from './constants'

import { SidecarEmitter } from './sidecar-emitter'
import {
  isSidecarPayloadHook,
  isSidecarPayloadLog,
  SidecarPayloadHook,
  SidecarPayloadLog,
}                                   from './payload-schemas'

/**
 * Frida: Spawning vs. attaching
 * https://summit-labs.frida.ninja/frida-tool-reference/frida
 */
export enum SpawnMode {
  Default = 0,
  Always  = 1,
  Never   = 2,
}

export interface SidecarBodyOptions {
  initAgentScript? : string,
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
  initAgentScript? : string
  spawnMode        : SpawnMode
  targetProcess?   : frida.TargetProcess

  /**
   * Whether the attached process has been spawned by Sidecar:
   *  If yes, then sidecar should destroy the process when `detach`
   *  If no, then the sidecar should leave the process as it is when `detach`
   */
  spawnPid?: number

  constructor (
    options?: SidecarBodyOptions,
  ) {
    super()
    log.verbose('SidecarBody', 'constructor(%s)',
      options
        ? `"${JSON.stringify(options)}`
        : '',
    )

    this.initAgentScript  = options?.initAgentScript
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
     * 1. initAgentScript
     */
    if (this.initAgentScript) {
      log.silly('SidecarBody', '[INIT_SYMBOL]() initAgentScript has been specified from constructor args')
    } else {
      log.silly('SidecarBody', '[INIT_SYMBOL]() load initAgentScript from metadata')
      this.initAgentScript = metadata.initAgentScript || ''
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
      initAgentScript: this.initAgentScript || metadata.initAgentScript,
    })

    this.emit(INIT_SYMBOL)
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
            this.emit('error', e as Error)
            return
          }

          try {
            pid = await frida.spawn(this.targetProcess)
            this.spawnPid = pid

            log.silly('SidecarBody',
              '[ATTACH_SYMBOL]() spawn(%s) succeed: pid = %s',
              this.targetProcess,
              pid,
            )
            session = await frida.attach(pid)
          } catch (e) {
            log.error('SidecarBody',
              '[ATTACH_SYMBOL]() spawn(%s) failed: %s\n%s',
              e && (e as Error).message,
              e && (e as Error).stack,
            )
            this.emit('error', e as Error)
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
        this.spawnPid = pid

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

    this.emit(ATTACH_SYMBOL)

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

    const script   = this.script
    const session  = this.session
    const spawnPid = this.spawnPid

    this.script   = undefined
    this.session  = undefined
    this.spawnPid = undefined

    if (!script || script.isDestroyed) {
      /**
       * Clean the system sliencely when the script has already been cleaned
       */
      try {
        await script?.unload()
      } catch (e) {
        log.silly('SidecarBody', '[DETACH_SYMBOL]() this.script.unload() rejection: %s', e && (e as Error).message)
      }
      try {
        await session?.detach()
      } catch (e) {
        log.silly('SidecarBody', '[DETACH_SYMBOL]() this.session.detach() rejection: %s', e && (e as Error).message)
      }
      try {
        if (spawnPid) { await frida.kill(spawnPid) }
      } catch (e) {
        log.silly('SidecarBody', '[DETACH_SYMBOL]() frida.kill(%s) rejection: %s', spawnPid, e && (e as Error).message)
      }

      return
    }

    if (script) {
      /**
       * Only call `unload()` if script is not destroyed
       */
      try {
        await script.unload()
      } catch (e) {
        log.error('SidecarBody',
          '[DETACH_SYMBOL]() script.unload() rejection: %s\n%s',
          e && (e as Error).message,
          e && (e as Error).stack,
        )
        this.emit('error', e as Error)
      }
    }

    if (session) {
      try {
        await session.detach()
      } catch (e) {
        log.error('SidecarBody',
          '[DETACH_SYMBOL]() session.detach() rejection: %s\n%s',
          e && (e as Error).message,
          e && (e as Error).stack,
        )
        this.emit('error', e as Error)
      }
    } else {
      log.silly('SidecarBody', '[DETACH_SYMBOL]() this.session is undefined')
    }

    if (spawnPid) {
      try {
        await frida.kill(spawnPid)
      } catch (e) {
        this.emit('error', e as Error)
      }
    }

    this.emit(DETACH_SYMBOL)
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
        this.emit('error', e as Error)
      }
    }

  }

  /**
   * ScriptMessageHandler
   */
  private [SCRIPT_MESSAGRE_HANDLER_SYMBOL] (
    message : frida.Message,
    data    : null | Buffer,
  ) {
    log.silly('SidecarBody',
      '[SCRIPT_MESSAGRE_HANDLER_SYMBOL](%s, %s)',
      JSON.stringify(message),
      data,
    )
    switch (message.type) {
      case frida.MessageType.Send:
        log.silly('SidecarBody',
          '[SCRIPT_MESSAGRE_HANDLER_SYMBOL]() MessageType.Send: %s',
          JSON.stringify(message.payload),
        )

        if (isSidecarPayloadLog(message.payload)) {
          this[LOG_EVENT_HANDLER](message.payload.payload)
        } else if (isSidecarPayloadHook(message.payload)) {
          this[HOOK_EVENT_HANDLER](message.payload.payload)

        } else {
          /**
           * Unknown payload type
           */
          log.warn('SidecarBody',
            '[SCRIPT_MESSAGRE_HANDLER_SYMBOL](): unknown payload type %s: %s',
            message.payload.type,
            JSON.stringify(message.payload)
          )
          this.emit('error',
            new Error([
              'SidecarBody got unknown message from Frida Agent:',
              'Payload:',
              JSON.stringify(message.payload, null, 2),
            ].join('\n'))
          )
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

  private [LOG_EVENT_HANDLER] (
    payload: SidecarPayloadLog['payload'],
  ) {
    const prefix = `SidecarBody<${payload.prefix}>`
    switch (payload.level) {
      case 'verbose':
        log.verbose(prefix, payload.message)
        break

      case 'silly':
        log.silly(prefix, payload.message)
        break

      default:
        throw new Error('unknown log payload: ' + JSON.stringify(payload))
    }
  }

  private [HOOK_EVENT_HANDLER] (
    payload: SidecarPayloadHook['payload'],
  ) {
    log.verbose('SidecarBody',
      '[HOOK_EVENT_HANDLER]("%s")',
      JSON.stringify(payload),
    )

    this.emit(
      payload.method,
      payload.args,
    )
  }

}

export { SidecarBody }
