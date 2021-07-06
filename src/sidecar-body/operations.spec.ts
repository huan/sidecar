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

import {
  INIT_SYMBOL,
  ATTACH_SYMBOL,
  DETACH_SYMBOL,
}                 from './constants'

const targetProgram = () =>
  process.platform        === 'linux'   ? '/bin/ls'
    : process.platform    === 'darwin'  ? '/bin/ls'
      : process.platform  === 'win32'   ? 'c:\\Windows\\notepad.exe'
        : 'targteProgram(): Unknown process.platform:' + process.platform

test('init()', async t => {

  @Sidecar(targetProgram())
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })
  const future = new Promise<void>(resolve => s.on(INIT_SYMBOL, resolve))

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

  @Sidecar(targetProgram())
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })

  s.script = {
    unload: (..._: any[]) => { return {} as any },
  } as any
  s.session = {
    detach: (..._: any[]) => { return {} as any },
  } as any

  const future = new Promise<void>(resolve => s.on(ATTACH_SYMBOL, resolve))

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
    await detach(s)
  }
})

test('detach()', async t => {

  @Sidecar(targetProgram())
  class SidecarTest extends SidecarBody {}

  const s = new SidecarTest({ spawnMode: SpawnMode.Always })
  const future = new Promise<void>(resolve => s.on(DETACH_SYMBOL, resolve))

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
