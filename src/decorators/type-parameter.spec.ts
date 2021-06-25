#!/usr/bin/env ts-node
/* eslint-disable padded-blocks */

import test  from 'tstest'

import {
  getParameterType,
  TypeParameter,
  PARAMETER_TYPE_SYMBOL,
}                         from './type-parameter'

test('@TypeParameter with metadata', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  class Test {

    method (
      n: number,
      @TypeParameter(
        NATIVE_TYPE,
        ...POINTER_TYPE_LIST,
      ) content: string,
    ) {
      void n
      void content
    }

  }

  const instance = new Test()
  const data = Reflect.getMetadata(
    PARAMETER_TYPE_SYMBOL,
    instance,
    'method',
  )

  /* eslint-disable no-sparse-arrays */
  const EXPECTED_DATA = [, [
    NATIVE_TYPE,
    ...POINTER_TYPE_LIST,
  ]]
  t.deepEqual(data, EXPECTED_DATA, 'should get the parameter type data')
})

test('getParameterType', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  class Test {

    method (
      n: number,
      @TypeParameter(
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
