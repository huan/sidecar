import path from 'path'
import { SidecarMetadata } from '../decorators/mod'

function moduleName (
  this: SidecarMetadata,
) {
  const targetProcess = this.targetProcess
  if (!targetProcess) {
    throw new Error('no targetProcess found in SidecarMetadata')
  }

  return typeof targetProcess === 'number'
    ? targetProcess
    : path.basename(targetProcess)
}

export { moduleName }
