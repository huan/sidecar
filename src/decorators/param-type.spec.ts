#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  getParamType,
  TypeParameter,
  PARAM_TYPE_SYMBOL,
}                         from './param-type'

test('ParamType with metadata', async t => {
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
    PARAM_TYPE_SYMBOL,
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

test('getParamType', async t => {
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
  const typeList = [0, 1].map(i => getParamType(
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
