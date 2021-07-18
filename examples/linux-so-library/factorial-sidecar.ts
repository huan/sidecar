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
 */
import path from 'path'

import {
  Call,
  Ret,
  Sidecar,
  SidecarBody,
  RetType,
  ParamType,
  exportTarget,
}                   from '../../src/mod'

const libFile = path.join(
  __dirname,
  'libfactorial.so',
)

const initAgentScript = `
  Module.load('${libFile}')
`

@Sidecar(
  ['/bin/sleep', ['10']],
  initAgentScript,
)
class FactorialSidecar extends SidecarBody {

  @Call(exportTarget('factorial', 'libfactorial.so'))
  @RetType('uint64')
  factorial (
    @ParamType('int') n: number,
  ): Promise<number> { return Ret(n) }

}

export { FactorialSidecar }
