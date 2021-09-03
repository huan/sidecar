import type { SidecarMetadata } from '../../src/decorators/mod.js'

/**
 * Sidecar View Fixtures
 */
const SIDECAR_METADATA: SidecarMetadata = {
  interceptorList: [
    {
      address: {
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
        target: {
          address    : '0x17',
          moduleName : null,
          type       : 'address',
        },
      },
    },
  ],
  nativeFunctionList: [
    {
      address: {
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
        target: {
          address: '0x4d',
          moduleName: null,
          type: 'address',
        },
      },
    },
    {
      address: {
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
        target: {
          address: '0x42',
          moduleName: null,
          type: 'address',
        },
      },
    },
    {
      export: {
        name: 'pointerMethod',
        paramTypeList: [
          [
            'pointer',
          ],
        ],
        retType: [
          'pointer',
        ],
        target: {
          exportName: 'MessageBoxW',
          moduleName: 'user32.dll',
          type: 'export',
        },
      },
    },
    {
      address: {
        name: 'voidMethod',
        paramTypeList: [],
        retType: ['void'],
        target: {
          address    : '0x1234',
          moduleName : 'test',
          type       : 'address',
        },
      },
    },
    { // AgentType: should not be decorated by neither @ParamType nor @RetType
      agent: {
        name: 'agentMethod',
        paramTypeList: [],
        retType: undefined,
        target: {
          funcName : 'agentFunctionName',
          type     : 'agent',
        },
      },
    },
  ],
  sidecarTarget: {
    target: 'chatbox-linux',
    type: 'process',
  },
}

function getSidecarMetadataFixture (): SidecarMetadata {
  // https://stackoverflow.com/a/12690181/1123955
  return JSON.parse(JSON.stringify(SIDECAR_METADATA))
}

export { getSidecarMetadataFixture }
