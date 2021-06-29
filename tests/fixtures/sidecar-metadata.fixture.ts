import { SidecarMetadata } from '../../src/decorators/sidecar/sidecar-metadata'

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

export { SIDECAR_METADATA }
