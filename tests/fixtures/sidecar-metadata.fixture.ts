import { SidecarMetadata } from '../../src/decorators/sidecar/sidecar-metadata'

/**
 * Sidecar Metada Fixtures
 */
const SIDECAR_METADATA: SidecarMetadata = {
  call: {
    anotherCall: 77,
    testMethod: 66,
  },
  hook: {
    hookMethod: 23,
  },
  paramType: {
    anotherCall: [
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
    hookMethod: [
      [
        'int',
      ],
      [
        'pointer',
        'Utf8String',
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
    anotherCall: [
      'pointer',
      'Int',
    ],
    testMethod: [
      'pointer',
      'Utf8String',
    ],
  },
}

function getSidecarMetadataFixture (): SidecarMetadata {
  // https://stackoverflow.com/a/12690181/1123955
  return JSON.parse(JSON.stringify(SIDECAR_METADATA))
}

export { getSidecarMetadataFixture }
