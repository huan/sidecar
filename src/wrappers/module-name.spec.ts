#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { SidecarTargetObjSpawn } from '../decorators/sidecar/target'

import { moduleName } from './module-name'

test('moduleName() spawn with linux path', async t => {
  const DATA = {
    type: 'spawn',
    target: [
      '/usr/bin/command',
      ['arg1'],
    ],
  } as SidecarTargetObjSpawn
  const EXPECT = 'command'
  const result = moduleName.call({
    sidecarTarget: DATA,
  } as any)
  t.equal(result, EXPECT, 'should get module name from spawn for linux path')
})

test('moduleName() spawn with windows path', async t => {
  const DATA = {
    type: 'spawn',
    target: [
      'C:\\Program Files\\folder\\command.exe',
      ['arg1'],
    ],
  } as SidecarTargetObjSpawn
  const EXPECT = 'command.exe'
  const result = moduleName.call({
    sidecarTarget: DATA,
  } as any)
  t.equal(result, EXPECT, 'should get module name from spawn for windows path')
})
