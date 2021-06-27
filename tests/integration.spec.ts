#!/usr/bin/env ts-node

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

@Sidecar('messaging', {
  initAgent: 'console.log("Sidecar inited")',
})
class MessagingSidecar extends SidecarBody {

  @Call(0x1234)
  @RetType('pointer', 'Utf8String')
  mo (
    @ParamType('pointer', 'Utf8String')  content:  string,
    @ParamType('pointer', 'Int')         count:    number,
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

test('test', async (t) => {
  const sidecar = new MessagingSidecar()

  sidecar.on('hook', payload => {
    console.log('method:', payload.method)
    console.log('args:', payload.args)
  })

  const ret = await sidecar.mo('hello', 2)
  console.log('ret:', ret)

  t.true(sidecar, 'tbw')
})
