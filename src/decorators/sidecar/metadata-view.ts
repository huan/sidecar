import {
  log,
}               from '../../config'

import { SIDECAR_SYMBOL } from './constants'
import { SidecarView } from '../../agent/sidecar-view'

function updateMetadataView (
  target : any,
  view   : SidecarView,
): void {
  log.verbose('Sidecar', 'updateMetadataView(%s, %s)',
    target.name,
    JSON.stringify(view)
  )
  // Update the parameter names
  Reflect.defineMetadata(
    SIDECAR_SYMBOL,
    view,
    target,
  )
}

function getMetadataView (
  target      : Object,
): undefined | SidecarView {
  // Pull the array of parameter names
  const view = Reflect.getMetadata(
    SIDECAR_SYMBOL,
    target,
  )
  return view
}

export {
  getMetadataView,
  updateMetadataView,
}
