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
import {
  Sidecar,
  SidecarBody,
  Call,
  Hook,
  ParamType,
  RetType,
  Ret,
  VERSION,
}           from 'frida-sidecar'

@Sidecar('test')
export class ChatboxSidecar extends SidecarBody {

  @Call(0x1234)
  @RetType('void')
  mo (
    @ParamType('pointer', 'Utf8String') content: string,
  ): Promise<string> {
    return Ret(content)
  }

  @Hook(0x5678)
  mt (
    @ParamType('pointer', 'Utf8String') content: string,
  ) {
    return Ret(content)
  }

}

async function main () {
  if (VERSION === '0.0.0') {
    throw new Error('VERSION not set!')
  }
  const sidecar = new ChatboxSidecar()
  sidecar.on('hook', payload => console.log(payload))

  return 0
}

/**
 * https://stackoverflow.com/a/6398335/1123955
 */
if (require.main === module) {
  main()
  .then(process.exit)
  .catch(e => {
    console.error(e)
    process.exit(1)
  })
}

