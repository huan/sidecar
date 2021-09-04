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
import path from 'path'

import type { FunctionTarget } from '../../src/function-target.js'

import { codeRoot } from '../../src/cjs.js'

/**
 * See: https://github.com/frida/frida-node/blob/master/test/data/index.ts
 */
function targetProgram () {
  const chatboxNameList = [
    'chatbox',
    '-',
    process.platform,
  ]

  if (process.platform === 'win32') {
    chatboxNameList.push('.exe')
  }

  return path.resolve(
    codeRoot,
    'examples',
    'chatbox',
    chatboxNameList.join(''),
  )
}

interface TargetAddressConfig {
  [platform: string]: {
    [arch: string]: {
      [call: string]: FunctionTarget,
    }
  }
}

const chatboxConfig: TargetAddressConfig = {
  darwin: {
    arm64: {
      mo: 0x3d88,
      mt: 0x3dc8,
    },
  },
  linux: {
    x64: {
      mo: 0x11e9,
      mt: 0x121f,
    },
  },
  win32: {
    x64: {
      mo: 0x0,
      mt: 0x0,
    },
  },
}

const targetAddressConfig = (config: TargetAddressConfig) => (
  call: string,
) => config[
  process.platform
]![
  process.arch
]![
  call
]!

const targetAddress = targetAddressConfig(chatboxConfig)

export {
  targetProgram,
  targetAddress,
}
