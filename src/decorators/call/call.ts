import {
  log,
}                 from '../../config'

import {
  FunctionTarget,
}                 from '../../frida'

import { updateMetadataCall }   from './metadata-call'
import { updateRpcDescriptor }  from './update-rpc-descriptor'

function Call (
  functionTarget: FunctionTarget,
) {
  log.verbose('Sidecar', '@Call(%s)',
    typeof functionTarget === 'object' ? JSON.stringify(functionTarget)
      : typeof functionTarget === 'number' ? functionTarget.toString(16)
        : functionTarget,
  )

  return function callMethodDecorator (
    target      : Object,
    propertyKey : string,
    descriptor  : PropertyDescriptor,
  ): PropertyDescriptor {
    log.verbose('Sidecar',
      '@Call(%s) callMethodDecorator(%s, %s, descriptor)',
      typeof functionTarget === 'object' ? JSON.stringify(functionTarget)
        : typeof functionTarget === 'number' ? functionTarget.toString(16)
          : functionTarget,

      target.constructor.name,
      propertyKey,
    )

    updateMetadataCall(
      target,
      propertyKey,
      functionTarget,
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
