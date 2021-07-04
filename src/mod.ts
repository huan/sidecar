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
