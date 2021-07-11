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
}           from '../src/mod'

import { ChatboxSidecar } from './chatbox-sidecar'

async function main () {
  const sidecar = new ChatboxSidecar()
  await attach(sidecar)

  /**
   * 1. Hook sidecar.mt(...)
   */
  sidecar.on('mt', args => {
    console.log('Sidecar: hook mt args: "' + JSON.stringify(args) + '"')
  })

  /**
   * 2. Call sidecar.mo(...)
   */
  const timer = setInterval(async () => {
    const ret = await sidecar.mo('Sidecar: greeting from timer interval!')
    console.log('Sidecar: called mo() to send message, ret is ' + ret)
  }, 5 * 1000)

  const clean = async () => {
    clearInterval(timer)
    await detach(sidecar)
  }

  process.on('SIGINT',  clean)
  process.on('SIGTERM', clean)
}

main()
  .catch(console.error)
