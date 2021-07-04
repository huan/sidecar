/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import { log } from 'brolog'

import * as frida from '../../../src/frida'

import { clean }                  from './clean'
import { loadAgentSource }        from './load-agent-source'
import { scriptDestroyedHandler } from './script-destroyed-handler'
import { scriptMessageHandler }   from './script-message-handler'

log.level('silly')

const scriptPostTest = (script: frida.Script) => () => {
  return script.post({
    data: 'XXX OOO',
    type: 'test',
  })
}
async function main () {
  const session     = await frida.attach('messaging')
  const agentSource = await loadAgentSource()
  const script      = await session.createScript(agentSource)

  script.message.connect(scriptMessageHandler)
  script.destroyed.connect(scriptDestroyedHandler)

  process.on('SIGINT',  () => clean(session, script))
  process.on('SIGTERM', () => clean(session, script))

  await script.load()

  const timer = setInterval(scriptPostTest(script), 1000)
  ;(timer as any).unref()

  try {
    await script.exports.init()
  } catch (e) {
    console.error(e)
  }
  // frida.resume(pid)
  try {
    await script.exports.mo('Sidebar: new messsage send by script.exports.mo()')
  } catch (e) {
    console.error(e)
  }
}

main()
  .catch(console.error)
