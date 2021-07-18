#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  normalizeSidecarTarget,
  SidecarTargetRawSpawn,
  SidecarTargetObjSpawn,
  isSidecarTargetSpawn,
  isSidecarTargetProcess,
}                           from './target'

test('normalizeSidecarTarget() processTarget: number', async t => {
  const TARGET = 0x1234
  const EXPECTED = {
    target: TARGET,
    type: 'process',
  }

  const actual = normalizeSidecarTarget(TARGET)
  t.deepEqual(actual, EXPECTED, 'should normalize number to process target')

  t.true(isSidecarTargetProcess(actual), 'should be a process target')
})

test('normalizeSidecarTarget() processTarget: string', async t => {
  const TARGET = 'namedTarget'
  const EXPECTED = {
    target: TARGET,
    type: 'process',
  }

  const actual = normalizeSidecarTarget(TARGET)
  t.deepEqual(actual, EXPECTED, 'should normalize string to process target')

  t.true(isSidecarTargetProcess(actual), 'should be a process target')
})

test('normalizeSidecarTarget() spawnTarget: []', async t => {
  const TARGET = [
    'command',
    [
      'arg1',
      'arg2',
    ],
  ] as SidecarTargetRawSpawn
  const EXPECTED = {
    target: TARGET,
    type: 'spawn',
  }

  const actual = normalizeSidecarTarget(TARGET)
  t.deepEqual(actual, EXPECTED, 'should normalize array to spawn target')

  t.true(isSidecarTargetSpawn(actual), 'should be a spawn target')
})

test('normalizeSidecarTarget() obj: {}', async t => {
  const TARGET = {
    target: [
      'command',
      ['arg1'],
    ],
    type: 'spawn',
  } as SidecarTargetObjSpawn

  const actual = normalizeSidecarTarget(TARGET)
  t.deepEqual(actual, TARGET, 'should normalize obj unchanged')

  t.true(isSidecarTargetSpawn(actual), 'should be a spawn target')
})

test('normalizeSidecarTarget() undefined', async t => {
  const TARGET = undefined
  const actual = normalizeSidecarTarget(TARGET)
  t.deepEqual(actual, undefined, 'should normalize undefined to undefined')

  t.false(isSidecarTargetSpawn(actual), 'should not be a spawn target')
  t.false(isSidecarTargetProcess(actual), 'should not be a process target')
})
