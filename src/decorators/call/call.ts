import {
  log,
}                 from '../../config'

import {
  FridaTarget,
  LabelTarget,
}                 from '../../frida'

import { updateMetadataCallTarget } from './metadata-call-target'
import { updateRpcDescriptor }      from './update-rpc-descriptor'

const Call = (
  fridaTarget: FridaTarget | LabelTarget,
) => (
  target      : Object,
  propertyKey : string,
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

  const rpcDescriptor = updateRpcDescriptor(
    target,
    propertyKey,
    descriptor,
  )

  return rpcDescriptor
}

export { Call }
