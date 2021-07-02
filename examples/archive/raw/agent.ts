/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import { log } from 'brolog'

log.level('silly')
log.verbose('Agent', 'Entered')

const MO_ADDR = ptr(0x5631598e21c9)
const MT_ADDR = ptr(0x5631598e21f4)

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

Interceptor.attach(
  MT_ADDR,
  {
    onEnter: args => {
      log.verbose('Agent', 'Interceptor.attach() onEnter(%s)', args[0].readUtf8String())
      send({
        payload: {
          content: args[0].readUtf8String(),
        },
        type: 'MT_MESSAGE',
      })
    },
  }
)

const fridaRecv: MessageCallback = (message: any, data: ArrayBuffer | null) => {
  log.verbose('Agent', 'fridaRec(%s, %s)', JSON.stringify(message), data)
  mo(JSON.stringify(message))
  recv(fridaRecv)
}

log.verbose('Agent', 'recv(fridaRecv) registering...')
recv(fridaRecv)
log.verbose('Agent', 'recv(fridaRecv) registered')

function init () {
  log.verbose('Agent', 'init()')
}

rpc.exports = {
  init,
  mo,
}
