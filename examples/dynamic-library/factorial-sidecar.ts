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
import { SidecarTargetRawSpawn } from '../../src/decorators/sidecar/target'

import {
  Call,
  Ret,
  Sidecar,
  SidecarBody,
  RetType,
  ParamType,
  exportTarget,
}                   from '../../src/mod'

/**
 * Inspired by https://github.com/iddoeldor/frida-snippets#socket-activity
 */
const libFileConfig: {
  [k in NodeJS.Platform]?: string
} = {
  darwin : 'libfactorial.dylib',
  linux  : 'libfactorial-x64.so',
  win32  : 'libfactorial-x64.dll',
}

const spawnTargetConfig: {
  [k in NodeJS.Platform]?: SidecarTargetRawSpawn
} = {
  darwin : ['/bin/sleep', ['10']],
  linux  : ['/bin/sleep', ['10']],
  win32  : ['C:\\Windows\\notepad.exe'],
}

const libFile     = libFileConfig[process.platform]
const spawnTarget = spawnTargetConfig[process.platform]

if (!libFile || !spawnTarget) {
  console.error(`process.platform: ${process.platform} is not supported yet.`)
  throw new Error('no libFile or spawnTarget found!')
}

console.log([
  'libFile:',
  libFile,
  '\n',
  'spawnTarget:',
  spawnTarget,
].join(''))

const libPath = path.join(
  __dirname,
  libFile,
).replace(/\\/g, '\\\\')

const initAgentScript = `Module.load('${libPath}')`

@Sidecar(
  spawnTarget,
  initAgentScript,
)
class FactorialSidecar extends SidecarBody {

  @Call(exportTarget('factorial', libFile))
  @RetType('uint64')
  factorial (
    @ParamType('int') n: number,
  ): Promise<number> { return Ret(n) }

}

export { FactorialSidecar }
