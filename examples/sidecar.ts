/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
import * as frida from 'frida'

import fs from 'fs'
import ts from 'typescript'

function clean (
  session: frida.Session,
  script: frida.Script,
): void {
  script.unload().catch(console.error)
  session.detach().catch(console.error)
}

async function getAgentSource (): Promise<string> {
  const agentTypeScriptSource = (
    await fs.promises.readFile(
      require.resolve('./sidecar-agent.ts')
    )
  ).toString()
  const agentSource = ts.transpile(agentTypeScriptSource)
  return agentSource
}
async function main () {
  // const pid = frida.spawn(['/bin/ls'])
  const session = await frida.attach('messaging')

  const agentSource = await getAgentSource()
  const script = await session.createScript(agentSource)

  process.on('SIGINT',  () => clean(session, script))
  process.on('SIGTERM', () => clean(session, script))

  await script.load()

  try {
    await script.exports.init()
  } catch (e) {
    console.error(e)
  }
  // frida.resume(pid)

  try {
    await script.exports.mo('test')
  } catch (e) {
    console.error(e)
  }
}

main()
  .catch(console.error)
