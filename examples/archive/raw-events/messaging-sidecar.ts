/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import { EventEmitter } from 'events'
import { log } from 'brolog'

import * as frida from './frida'
import type { SidecarFridaPayload } from './schema.js'
import { loadAgentSource }        from './load-agent-source.js'

class MessagingSidecar extends EventEmitter {

  private session?: frida.Session
  private script?: frida.Script

  constructor () {
    super()
    log.verbose('MessagingSidecar', 'constructor()')
  }

  public async init () {
    log.verbose('MessagingSidecar', 'init()')

    const session     = await frida.attach('messaging')
    const agentSource = await loadAgentSource()
    const script      = await session.createScript(agentSource)

    script.message.connect(this.scriptMessageHandler.bind(this))
    script.destroyed.connect(this.scriptDestroyedHandler.bind(this))

    await script.load()

    this.session = session
    this.script = script
  }

  public async start () {
    log.verbose('MessagingSidecar', 'stop()')

    if (!this.script) {
      throw new Error('stop() this.script is undefined!')
    }

    await this.script.exports['init']!()
  }

  public async stop () {
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

  /**
   * ScriptMessageHandler
   */
  private scriptMessageHandler (
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

        this.emitPayload(
          message.payload as SidecarFridaPayload,
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

  private emitPayload (
    payload: SidecarFridaPayload,
    data: null | Buffer,
  ) {
    log.verbose('MessagingSidecar',
      'emitPayload(%s, %s)',
      payload,
      data,
    )

    this.emit('hook', payload)
  }

  /**
   * ScriptDestroyedHandler
   */
  private scriptDestroyedHandler () {
    log.verbose('MessagingSidecar', 'scriptDestroyedHandler()')
  }

  public async mo (content: string): Promise<void> {
    log.verbose('MessagingSidecar', 'mo(%s)', content)

    try {
      await this.script!.exports['mo']!('MessagingSidebar: new messsage send by script.exports.mo()')
    } catch (e) {
      console.error(e)
    }
  }

}

export { MessagingSidecar }
