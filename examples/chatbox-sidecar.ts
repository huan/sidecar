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
  agentTarget,
}                 from '../src/mod'

import {
  targetAddress,
  targetProgram,
}                 from './sidecar-config'

import {
  loadAgentSource,
}                   from './load-agent-source'

void targetAddress
void agentTarget

@Sidecar(
  targetProgram(),    // chatbox-linux
  loadAgentSource(),  // $!#%$#T^@#$!@!
)
class ChatboxSidecar extends SidecarBody {

  @Call(/* 0x55d6daf341c9 */ targetAddress('mo'))
  // @Call(agentTarget('agentMo')
  @RetType('void')
  mo (
    @ParamType('pointer', 'Utf8String') content: string,
  ): Promise<string> { return Ret(content) }

  @Hook(/* 0x55d6daf341c9 */ targetAddress('mt'))
  // @Hook(agentTarget('agentMt_PatchCode')
  mt (
    @ParamType('pointer', 'Utf8String') content: string,
  ) { return Ret(content) }

}

export { ChatboxSidecar }
