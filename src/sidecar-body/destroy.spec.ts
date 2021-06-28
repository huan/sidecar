#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  SidecarBody,
}                         from './sidecar-body'
import { destroy } from './destroy'

test('SidecarBody destroy event', async t => {

  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest()
  const future = new Promise<void>(resolve => s.on('destroy', resolve))

  try {
    await destroy(s)

    await Promise.race([
      future,
      new Promise((resolve, reject) => {
        void resolve
        setTimeout(reject, 100)
      }),
    ])

    t.pass('destroy() successfully')
  } catch (e) {
    t.fail('Rejection:' + e && e.message)
  }
})
