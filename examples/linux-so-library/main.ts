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
 */
import assert from 'assert'

import {
  attach,
  detach,
}           from '../../src/mod'

import { FactorialSidecar } from './factorial-sidecar'

async function main () {
  const sidecar = new FactorialSidecar()
  console.log('Sidecar attaching...')
  await attach(sidecar)
  console.log('Sidecar attached.')

  const ret = await sidecar.factorial(3)

  assert(typeof ret === 'number', 'factorial() returns type `number`')
  assert(ret === 6, 'factorial(3)=6')

  console.log('factorial(3)=' + ret)

  await detach(sidecar)
}

main()
  .catch(console.error)
