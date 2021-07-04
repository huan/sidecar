import { SidecarMetadata } from '../../src/decorators/mod'

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
        target: '0x17',
        type: 'address',
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
        target: '0x4d',
        type: 'address',
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
        target: '0x42',
        type: 'address',
      },
    },
  ],
  targetProcess: 'chatbox-linux',
}

function getSidecarMetadataFixture (): SidecarMetadata {
  // https://stackoverflow.com/a/12690181/1123955
  return JSON.parse(JSON.stringify(SIDECAR_METADATA))
}

export { getSidecarMetadataFixture }
