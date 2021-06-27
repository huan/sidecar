import {
  log,
}                 from '../../config'

import {
  FridaTarget,
  LabelTarget,
}                 from '../../frida'

import { updateMetadataCallTarget } from './metadata-call-target'

const Call = (
  fridaTarget: FridaTarget | LabelTarget,
) => (
  target      : Object,
  propertyKey : string | symbol,
  descriptor  : PropertyDescriptor,
): PropertyDescriptor => {
  log.verbose('Sidecar',
    'Call(%s) => (%s, %s)',
    fridaTarget,
    target.constructor.name,
    propertyKey,
  )

  updateMetadataCallTarget(
    target,
    propertyKey,
    fridaTarget,
  )

  // Huan(202106) TODO: add a replaced function to show a error message when be called.
  return descriptor
}

export { Call }
