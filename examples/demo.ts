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

  sidecar.on('mt', args => {
    console.log('mt args:', args)
  })

  await sidecar.mo('Sidecar: this message is from sidecar.mo()')

  /**
   * Call sidecar.mo(...) periodly
   */
  const timer = setInterval(async () => {
    await sidecar.mo('Sidecar: greeting from timer interval!')
  }, 5 * 1000)

  void timer
  void detach

  /**
   * detach after 10 seconds.
   */
  // setTimeout(async () => {
  //   void timer
  //   clearInterval(timer)
  //   await detach(sidecar)
  // }, 11 * 1000)

}

main()
  .catch(console.error)
