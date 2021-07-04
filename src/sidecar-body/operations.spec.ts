#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  SidecarBody,
  SpawnMode,
}                 from './sidecar-body'
import {
  init,
  attach,
  detach,
}                from './operations'
import { Sidecar } from '../decorators/mod'

test('init()', async t => {

  @Sidecar('/bin/ls')
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })
  const future = new Promise<void>(resolve => s.on('inited', resolve))

  try {
    await init(s)

    await Promise.race([
      future,
      new Promise((resolve, reject) => {
        void resolve
        setTimeout(reject, 100)
      }),
    ])

    t.pass('init() successfully')
  } catch (e) {
    t.fail('Rejection:' + e && e.message)
    console.error(e)
  }
})
test('attach()', async t => {

  @Sidecar('/bin/ls')
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })

  s.script = {
    unload: (..._: any[]) => { return {} as any },
  } as any
  s.session = {
    detach: (..._: any[]) => { return {} as any },
  } as any

  const future = new Promise<void>(resolve => s.on('attached', resolve))

  try {
    await attach(s)

    await Promise.race([
      future,
      new Promise((resolve, reject) => {
        void resolve
        setTimeout(reject, 100)
      }),
    ])
    t.pass('attach() successfully')
  } catch (e) {
    t.fail('Rejection:' + e && e.message)
  } finally {
      try { detach(s) }
      catch (e) { throw e }
    }
})

test('detach()', async t => {

  @Sidecar('/bin/ls')
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })
  const future = new Promise<void>(resolve => s.on('detached', resolve))

  try {
    await init(s)
    await attach(s)

    await detach(s)

    await Promise.race([
      future,
      new Promise((resolve, reject) => {
        void resolve
        setTimeout(reject, 100)
      }),
    ])

    t.pass('detach() successfully')
  } catch (e) {
    t.fail('Rejection:' + e && e.message)
  }
})
