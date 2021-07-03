import { SidecarMetadataFunctionDescription } from '../decorators/mod'

function hexAddress (
  this: SidecarMetadataFunctionDescription,
) {
  const address = this.target
  return typeof address === 'number'
    ? `0x${address.toString(16)}`
    : address
}

export { hexAddress }
