import {
  log,
}                 from '../../config'

import {
  FridaTarget,
  LabelTarget,
}                 from '../../frida'

import { updateMetadataCall }   from './metadata-call'
import { updateRpcDescriptor }  from './update-rpc-descriptor'

function Call (
  fridaTarget: FridaTarget | LabelTarget,
) {
  log.verbose('Sidecar', '@Call(%s)',
    typeof fridaTarget === 'object' ? JSON.stringify(fridaTarget)
    : typeof fridaTarget === 'number' ? fridaTarget.toString(16)
    : fridaTarget,
  )

  return function callMethodDecorator (
    target      : Object,
    propertyKey : string,
    descriptor  : PropertyDescriptor,
  ): PropertyDescriptor {
    log.verbose('Sidecar',
      '@Call(%s) callMethodDecorator(%s, %s, descriptor)',
      typeof fridaTarget === 'object' ? JSON.stringify(fridaTarget)
      : typeof fridaTarget === 'number' ? fridaTarget.toString(16)
      : fridaTarget,

      target.constructor.name,
      propertyKey,
    )

    updateMetadataCall(
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
}

export { Call }
