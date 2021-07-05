#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { SidecarBodyEventPayloadHook, SidecarBodyEventPayloadLog } from '../../../sidecar-body/payload-schemas'

const {
  hookPayload,
  logPayload,
}               = require('./payload.js')

test('logPayload()', async t => {
  const message = 'test' as string

  const payload = logPayload(message)
  const EXPECTED: SidecarBodyEventPayloadLog = {
    payload : message,
    type    : 'log',
  }

  t.deepEqual(payload, EXPECTED, 'should get log payload correctly')
})

test('hookPayload()', async t => {
  const METHOD = 'method'
  const ARGS = ['arg0', 'arg1']

  const payload = hookPayload(
    METHOD,
    ARGS,
  )

  const EXPECTED_PAYLOAD: SidecarBodyEventPayloadHook = {
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
