#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { NativeType } from '../../frida'

import {
  guardRetType,
}                         from './guard-ret-type'

test('guard ret type', async t => {

  const triggerMetadata = (..._args: any[]) => {}

  class Test {

    // metadata will only be set when we have a decorator
    @triggerMetadata
    method (): string { // <--- `string` should be native type `pointer`
      return ''
    }

  }

  const test = new Test()

  const EXPECTED_RESULTS: [
    NativeType,
    boolean,    // `true` if the native type is compatible, `false` otherwise
  ][] = [
    ['int', false],
    ['pointer', true],
  ]

  for (const [nativeType, shouldMatch] of EXPECTED_RESULTS) {
    if (shouldMatch) {
      guardRetType(
        test,
        'method',
        nativeType,
      )
      t.pass('should not throw for nativeType: ' + nativeType)
    } else {
      t.throws(() => guardRetType(
        test,
        'method',
        nativeType,
      ), 'should throw for nativeType: ' + nativeType)
    }
  }
})
