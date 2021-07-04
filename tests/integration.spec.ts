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
  Call,
  Hook,
  Ret,
  Sidecar,
  SidecarBody,
  RetType,
  ParamType,
}                   from '../src/mod'

function getFixture () {
  @Sidecar('messaging', 'console.log("Sidecar inited")')
  class MessagingSidecar extends SidecarBody {

    @Call(0x1234)
    @RetType('pointer', 'Utf8String')
    mo (
      @ParamType('pointer', 'Utf8String') content:  string,
      @ParamType('int')                   count:    number,
    ): Promise<string> {
      return Ret(content, count)
    }

    @Hook({ label: 'label1' })
    mt (
      @ParamType('pointer', 'Utf8String') message: string,
    ) {
      return Ret(message)
    }

  }

  return MessagingSidecar
}

test('smoke testing', async (t) => {
  const MessagingSidecar = getFixture()
  const sidecar = new MessagingSidecar()

  sidecar.on('hook', payload => {
    console.log('method:', payload.method)
    console.log('args:', payload.args)
  })

  const EXPECTED_RET_VALUE = 42

  sidecar.script = {
    exports: {
      mo: () => Promise.resolve(EXPECTED_RET_VALUE),
    },
  } as any

  const ret = await sidecar.mo('hello', 2)
  t.equal(ret, EXPECTED_RET_VALUE, 'should get the proxyed method value from script')
})
