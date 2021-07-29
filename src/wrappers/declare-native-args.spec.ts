#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

import {
  declareNativeArgs,
}                       from './declare-native-args'

test('declareNativeArgs()', async t => {

  const fixture = getSidecarMetadataFixture()

  // console.log(fixture.nativeFunctionList.length)
  const result = fixture.nativeFunctionList
    .map(x => Object.values(x))
    .flat()
    .map(x => declareNativeArgs.call(x))

  // get the fixture
  // console.log(JSON.stringify(result, null, 2))

  const EXPECTED = [
    [
      '// pointer type for arg[0] -> Int',
      'const anotherCall_NativeArg_0 = Memory.alloc(1024 /*Process.pointerSize*/)',
      'anotherCall_NativeArg_0.writeInt(args[0])',
      '',
      '// pointer type for arg[1] -> Pointer -> Utf8String',
      'const anotherCall_NativeArg_1 = Memory.alloc(1024 /*Process.pointerSize*/)',
      'const anotherCall_Memory_1_0 = Memory.alloc(Process.pointerSize)',
      'anotherCall_NativeArg_1.writePointer(anotherCall_Memory_1_0)',
      'anotherCall_Memory_1_0.writeUtf8String(args[1])',
    ].join('\n'),
    [
      '// pointer type for arg[0] -> Utf8String',
      'const testMethod_NativeArg_0 = Memory.alloc(1024 /*Process.pointerSize*/)',
      'testMethod_NativeArg_0.writeUtf8String(args[0])',
      '',
      '// non-pointer type for arg[1]: int',
      'const testMethod_NativeArg_1 = args[1]',
    ].join('\n'),
    [
      '// pointer type for arg[0] -> ',
      'const pointerMethod_NativeArg_0 = ptr(Number(args[0]))',
    ].join('\n'),
    [
      '',
    ].join('\n'),
  ]
  // console.log('result.length: ', result.length)
  // console.log('EXPECTED.length: ', EXPECTED.length)
  t.deepEqual(result, EXPECTED, 'should declare the native args correctly.')
})
