import { SidecarView } from '../../src/frida-agent/views/sidecar-view'
/**
 * Sidecar Metada & View Fixtures
 */
const SIDECAR_VIEW: SidecarView = {
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
      name: 'anotherCall',
      paramTypeList: [
        [
          'pointer',
          'Int',
        ],
        [
          'pointer',
          'Pointer',
          'Utf8String',
        ],
      ],
      retType: [
        'pointer',
        'Int',
      ],
      target: 77,
    },
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

export { SIDECAR_VIEW }
