#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  ParamType,
}                         from './param-type'
import {
  getParamType,
}                         from './metadata-param-type'
import {
  PARAM_TYPE_SYMBOL,
}                         from './constants'

test('ParamType with metadata', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  class Test {

    method (
      n: number,
      @ParamType(
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
      @ParamType(
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

test('guard parameter native types', async t => {
  const NATIVE_TYPE       = 'pointer'
  const POINTER_TYPE_LIST = ['Pointer', 'Utf8String'] as const

  const getFixture = () => {
    class Test {

      method (
        n: number,
        @ParamType(
          NATIVE_TYPE,
          ...POINTER_TYPE_LIST,
        ) content: number,
      ) {
        void n
        void content
      }

    }

    return Test
  }

  // getFixture()
  t.throws(getFixture, 'should throw because the ParamType(pointer) is not match the design type `number`')
})
