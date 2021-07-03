import path from 'path'
import { SidecarView } from '../agent/sidecar-view'

function moduleName (
  this: SidecarView,
) {
  const targetProcess = this.targetProcess
  if (!targetProcess) {
    throw new Error('no targetProcess found in SidecarView')
  }

  return typeof targetProcess === 'number'
    ? targetProcess
    : path.basename(targetProcess)
}

export { moduleName }
