#!/usr/bin/env ts-node

import { test }  from 'tstest'

import {
  Sidecar,
  SidecarEmitter,
  Call,
  Hook,
  Ret,
  Param,
}                   from '../src/mod'

@Sidecar('messaging', {
  initFridaAgentSource: 'console.log("Sidecar inited")',
})
class MessagingSidecar extends SidecarEmitter {

  @Call(0x1234)
  @Type(['pointer', 'Utf8String'])
  mo (
    @Param(['pointer', 'Utf8String']) content: string,
    @Param(['pointer', 'Int']) count: number,
  ): string {
    return Ret(content, count)
  }

  @Hook(0x5678) mt (
    @Data('pointer', 'Utf8String') message: string,
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
