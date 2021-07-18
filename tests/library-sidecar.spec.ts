#!/usr/bin/env ts-node
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
import { test }  from 'tstest'

import {
  attach,
  detach,
}                   from '../src/mod'

import { FactorialSidecar } from '../examples/linux-so-library/factorial-sidecar'

test('library export function call', async (t) => {
  if (process.platform !== 'linux' && process.platform !== 'win32') {
    t.skip('This test will be skipped because it only support Linux(.so) and Windows(.dll) now')
    return
  }

  const sidecar = new FactorialSidecar()
  await attach(sidecar)

  const EXPECTED_RET_VALUE = 6
  const ret = await sidecar.factorial(3)

  await detach(sidecar)

  t.equal(ret, EXPECTED_RET_VALUE, 'should get the factorial(3) = 6')
})
