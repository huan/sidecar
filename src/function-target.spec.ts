#!/usr/bin/env ts-node
import { test }  from 'tstest'
import {
  addressTarget,
  agentTarget,
  moduleTarget,
  TargetPayloadAddress,
  TargetPayloadAgent,
  TargetPayloadModule,
}                 from './function-target'

test('AddressTarget()', async t => {
  const DATA     = 0x1234
  const EXPECTED: TargetPayloadAddress = {
    address    : '0x1234',
    moduleName : null,
    type       : 'address',
  }

  const result = addressTarget(DATA)

  t.deepEqual(result, EXPECTED, 'should get the correct address target for number')
})

test('AddressTarget() with module', async t => {
  const DATA     = 0x1234
  const MODULE_NAME = 'myModule'
  const EXPECTED: TargetPayloadAddress = {
    address    : '0x1234',
    moduleName : MODULE_NAME,
    type       : 'address',
  }

  const result = addressTarget(DATA, MODULE_NAME)

  t.deepEqual(result, EXPECTED, 'should get the correct address target for number and module name')
})

test('AgentTarget()', async t => {
  const DATA     = 'myPtr'
  const EXPECTED: TargetPayloadAgent = {
    type       : 'agent',
    varName    : DATA,
  }

  const result = agentTarget(DATA)

  t.deepEqual(result, EXPECTED, 'should get the correct agent target for var name')
})

test('ModuleTarget()', async t => {
  const DATA     = 'testExport'
  const EXPECTED: TargetPayloadModule = {
    exportName : DATA,
    moduleName   : null,
    type         : 'module',
  }

  const result = moduleTarget(DATA)

  t.deepEqual(result, EXPECTED, 'should get the correct module target for number')
})

test('ModuleTarget() with module', async t => {
  const DATA     = 'testExport'
  const MODULE_NAME = 'myModule'
  const EXPECTED: TargetPayloadModule = {
    exportName : DATA,
    moduleName   : MODULE_NAME,
    type         : 'module',
  }

  const result = moduleTarget(DATA, MODULE_NAME)

  t.deepEqual(result, EXPECTED, 'should get the correct module target for name and module name')
})
