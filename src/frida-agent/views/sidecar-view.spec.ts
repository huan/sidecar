#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  SidecarMetadata,
}                       from '../../decorators/mod'
import { sidecarView } from './sidecar-view'

test('sidecarView()', async t => {

  const METADATA: SidecarMetadata = {
    call: {
      testMethod: 66,
    },
    hook: {
      hookMethod: 23,
    },
    paramType: {
      hookMethod: [
        [
          'int',
        ],
      ],
      testMethod: [
        [
          'pointer',
          'Utf8String',
        ],
        [
          'int',
        ],
      ],
    },
    retType: {
      testMethod: [
        'pointer',
        'Utf8String',
      ],
    },
  }

  const EXPECTED_VIEW = {
    interceptorList: [
      {
        name: 'hookMethod',
        paramTypeList: [
          [
            'int',
          ],
        ],
        retType: undefined,
        target: 23,
      },
    ],
    nativeFunctionList: [
      {
        name: 'testMethod',
        paramTypeList: [
          [
            'pointer',
            'Utf8String',
          ],
          [
            'int',
          ],
        ],
        retType: [
          'pointer',
          'Utf8String',
        ],
        target: 66,
      },
    ],
  }

  const view = sidecarView(METADATA)
  // console.log(JSON.stringify(view, null, 2))
  t.deepEqual(view, EXPECTED_VIEW, 'should get the correct sidecar view for the metadata')
})
