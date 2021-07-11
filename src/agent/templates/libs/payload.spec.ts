#!/usr/bin/env ts-node
import { test }  from 'tstest'
import {
  SidecarPayloadHook,
  SidecarPayloadLog,
}                                 from '../../../sidecar-body/payload-schemas'

const {
  sidecarPayloadHook,
  sidecarPayloadLog,
}                       = require('./payload.js')

test('sidecarPayloadLog()', async t => {
  const message = 'test' as string

  const payload = sidecarPayloadLog(
    'verbose',
    'Test',
    message,
  )
  const EXPECTED: SidecarPayloadLog = {
    payload : {
      level: 'verbose',
      message,
      prefix: 'Test',
    },
    type    : 'log',
  }

  t.deepEqual(payload, EXPECTED, 'should get log payload correctly')
})

test('sidecarPayloadHook()', async t => {
  const METHOD = 'method'
  const ARGS = ['arg0', 'arg1']

  const payload = sidecarPayloadHook(
    METHOD,
    ARGS,
  )

  const EXPECTED_PAYLOAD: SidecarPayloadHook = {
    payload: {
      args   : {},
      method : METHOD,
    },
    type: 'hook',
  }
  for (const [idx, item] of ARGS.entries()) {
    EXPECTED_PAYLOAD.payload.args[idx] = item
  }

  t.deepEqual(payload, EXPECTED_PAYLOAD, 'should make hook payload correctly.')
})
