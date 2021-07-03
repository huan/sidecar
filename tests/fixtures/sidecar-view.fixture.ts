import { SidecarView } from '../../src/agent/sidecar-view'

/**
 * Sidecar View Fixtures
 */
const SIDECAR_VIEW: SidecarView = {
  interceptorList: [
    {
      name: 'hookMethod',
      paramTypeList: [
        [
          'int',
        ],
        [
          'pointer',
          'Utf8String',
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
  targetProcess: 'chatbox-linux-x64',
}

function getSidecarViewFixture (): SidecarView {
  // https://stackoverflow.com/a/12690181/1123955
  return JSON.parse(JSON.stringify(SIDECAR_VIEW))
}

export { getSidecarViewFixture }
