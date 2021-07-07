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
import { VERSION }      from './version'
import { Ret }          from './ret'
import {
  SidecarBody,
  attach,
  detach,
}                       from './sidecar-body/mod'

/**
 * Decorators
 */
import { Call }       from './decorators/call/mod'
import { Hook }       from './decorators/hook/mod'
import { ParamType }  from './decorators/param-type/mod'
import { RetType }    from './decorators/ret-type/mod'
import { Sidecar }    from './decorators/sidecar/mod'

export {
  VERSION,

  attach,
  detach,

  Call,
  Hook,
  ParamType,
  Ret,
  RetType,

  Sidecar,
  SidecarBody,
}
