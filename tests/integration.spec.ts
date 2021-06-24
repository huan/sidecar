#!/usr/bin/env ts-node

import { test }  from 'tstest'

import {
  Sidecar,
  Call,
  Hook,
  Ret,
  Param,
}                   from '../src/mod'

@Sidecar('messaging')
class MessagingSidecar {

  @Call(0x1234, [
    'pointer',
    'Utf8String',
  ])
  mo (
    @Param('char') content: string,
  ): number {
    return Ret(content)
  }

  @Hook(0x5678) mt (
    @Param('pointer', 'Utf8String') message: string,
  ) {
    return Ret(message)
  }

}

test('test', async (t) => {
  const sidecar = new MessagingSidecar()
  t.true(sidecar, 'tbw')
})
