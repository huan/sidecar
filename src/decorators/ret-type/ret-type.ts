import {
  NativeType,
  PointerType,
}               from '../../frida'
import {
  log,
}               from '../../config'

import {
  updateMetadataRetType,
}                         from './metadata-ret-type'
import { guardRetType }   from './guard-ret-type'

const RetType = (
  nativeType         : NativeType,
  ...pointerTypeList : PointerType[]
) => (
  target         : Object,
  propertyKey    : string | symbol,
  _descriptor     : PropertyDescriptor,
) => {
  log.verbose('Sidecar',
    'RetType(%s, %s) => (%s, %s)',
    nativeType,
    pointerTypeList.join(','),
    target.constructor.name,
    propertyKey,
  )

  guardRetType(
    target,
    propertyKey,
    nativeType,
  )

  updateMetadataRetType(
    target,
    propertyKey,
    [nativeType, ...pointerTypeList],
  )
}

export { RetType }
