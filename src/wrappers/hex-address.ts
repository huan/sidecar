import { SidecarFunctionDescription } from '../agent/sidecar-view'

function hexAddress (
  this: SidecarFunctionDescription,
) {
  const address = this.target
  return typeof address === 'number'
    ? `0x${address.toString(16)}`
    : address
}

export { hexAddress }
