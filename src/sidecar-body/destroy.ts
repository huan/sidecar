import { DESTROY_SYMBOL } from './constants'
import { SidecarBody } from './sidecar-body';

function destroy (
  sidecar: SidecarBody,
): Promise<void> {
  return sidecar[DESTROY_SYMBOL]()
}

export { destroy }
