#!/usr/bin/env ts-node
/* eslint-disable padded-blocks */

import test  from 'tstest'

import {
  Type,
  getMethodRetType,
  getParameterType,
}                         from './type'

test('Type parameter', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  class Test {

    method (
      n: number,
      @Type(
        NATIVE_TYPE,
        ...POINTER_TYPE_LIST,
      ) content: string,
    ) {
      void n
      void content
    }

  }

  const instance = new Test()
  const typeList = [0, 1].map(i => getParameterType(
    instance,
    'method',
    i,
  ))

  const EXPECTED_NAME_LIST = [undefined, [
    NATIVE_TYPE,
    ...POINTER_TYPE_LIST,
  ]]
  t.deepEqual(typeList, EXPECTED_NAME_LIST, 'should get decorated parameter type list')
})

test('Type method', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  class Test {

    @Type(
      NATIVE_TYPE,
      ...POINTER_TYPE_LIST,
    )
    method () {}

  }

  const instance = new Test()
  const typeList = getMethodRetType(
    instance,
    'method',
  )

  const EXPECTED_NAME_LIST = [
    NATIVE_TYPE,
    ...POINTER_TYPE_LIST,
  ]
  t.deepEqual(typeList, EXPECTED_NAME_LIST, 'should get decorated method ret type list')
})
