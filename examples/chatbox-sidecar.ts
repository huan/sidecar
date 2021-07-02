import {
  Sidecar,
  SidecarBody,
  Call,
  Hook,
  ParamType,
  RetType,
  Ret,
}                 from '../src/mod'

import {
  targetAddress,
  targetProgram,
}                 from './targets'

@Sidecar(targetProgram())
class ChatboxSidecar extends SidecarBody {

  @Call(targetAddress('mo'))
  @RetType('void')
  mo (
    @ParamType('pointer', 'Utf8String') content: string,
  ): Promise<string> {
    return Ret(content)
  }

  @Hook(targetAddress('mt'))
  mt (
    @ParamType('pointer', 'Utf8String') content: string,
  ) {
    return Ret(content)
  }

}

export { ChatboxSidecar }
