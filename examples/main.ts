/**
 *   Sidecar - https://github.com/huan/sidecar
 *
 *   @copyright 2021 Huan LI (李卓桓) <https://github.com/huan>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
import {
  attach,
  detach,
}           from '../src/mod.js'

/**
 * The `ChatboxSidecarPro` has more complicated settings
 *  You can read it and learn more in the [example](./chatbox-sidecar-pro.ts)
 */
import { ChatboxSidecarAgent }  from './chatbox-sidecar-agent/chatbox-sidecar-agent.js'
// import { ChatboxSidecarPro }  from './chatbox-sidecar-pro/chatbox-sidecar-pro.js'
// import { ChatboxSidecar } from './chatbox-sidecar.js'

async function main () {
  const sidecar = new ChatboxSidecarAgent()
  // const sidecar = new ChatboxSidecarPro()
  // const sidecar = new ChatboxSidecar()

  /**
   * 0. Initialize the sidecar by `attach()`
   */
  console.log('sidecar attaching...')
  await attach(sidecar)
  console.log('sidecar attached.')

  /**
   * 1. @Hook sidecar.mt(...)
   */
  sidecar.on('hook', async payload => {
    console.log(`sidecar @Hook() ${payload.method}() received message: "${payload.args[0]}"`)

    /**
     * 2. @Call sidecar.mo(...)
     */
    const reply = 'sidecar @Call() mt() greeting!'
    const ret = await sidecar.mo(reply)
    console.log(`replied with: "${reply}", ret: ${ret}\n`)
  })

  const clean = () => detach(sidecar)
  process.on('SIGINT',  clean)
  process.on('SIGTERM', clean)
}

main()
  .catch(console.error)
