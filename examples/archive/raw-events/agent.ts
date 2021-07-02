/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import { log } from 'brolog'

import { SidecarFridaPayload } from './schema'

log.level('verbose')
log.verbose('Agent', 'Entered')

const MO_ADDR = ptr(0x55555b6441c9)
const MT_ADDR = ptr(0x55555b6441f4)

const moNativeFunc = new NativeFunction(
  MO_ADDR,
  'void',
  ['pointer'],
)

function mo (content: string): void {
  log.verbose('Agent', 'mo(%s)', content)

  moNativeFunc(
    Memory.allocUtf8String(content)
  )
}

/**
 * To make sure the payload typing is right
 */
function sendSidecarPayload (
  payload: SidecarFridaPayload,
  data: null | number[] | ArrayBuffer,
) {
  send(payload, data)
}

Interceptor.attach(
  MT_ADDR,
  {
    onEnter: args => {
      log.silly('Agent', 'Interceptor.attach() onEnter(%s)', args[0].readUtf8String())
      const content = args[0].readUtf8String()
      const payload: SidecarFridaPayload = {
        args: {
          0: content,
          content,
        },
        method: 'mt',
      }
      sendSidecarPayload(payload, null)
    },
  }
)

function init () {
  log.verbose('Agent', 'init()')
}

rpc.exports = {
  init,
  mo,
}
