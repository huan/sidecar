import {
  ScriptMessageHandler,
  MessageType,
}                         from './frida'
import { log } from 'brolog'

const scriptMessageHandler: ScriptMessageHandler = (message, data) => {
  log.verbose('Sidecar', 'scriptMessageHandler(%s, %s)', JSON.stringify(message), data)
  switch (message.type) {
    case MessageType.Send:
      log.silly('Sidecar',
        'scriptMessagerHandler() MessageType.Send: %s',
        JSON.stringify(message.payload),
      )
      break
    case MessageType.Error:
      log.silly('Sidecar',
        'scriptMessagerHandler() MessageType.Error: %s',
        message.stack,
      )
      break

    default:
      throw new Error('Sidecar/scriptMessagerHandler() Error: unknown message type: ' + message)
  }

  if (data) {
    log.silly('Sidecar', 'scriptMessageHandler() data:', data)
  }
}

export { scriptMessageHandler }
