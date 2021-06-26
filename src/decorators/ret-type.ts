import {
  NativeType,
  PointerType,
}               from '../frida'
import {
  log,
}               from '../config'

const RET_TYPE_SYMBOL = Symbol('methodRetType')

function updateRetType (
  target         : Object,
  propertyKey    : string | symbol,
  typeList       : (NativeType | PointerType)[],
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    RET_TYPE_SYMBOL,
    typeList,
    target,
    propertyKey,
  )
}

function getRetType (
  target         : Object,
  propertyKey    : string | symbol,
): (NativeType | PointerType)[] {
  // Pull the array of parameter names
  const methodTypeList = Reflect.getMetadata(
    RET_TYPE_SYMBOL,
    target,
    propertyKey,
  )
  if (!Array.isArray(methodTypeList) || methodTypeList.length <= 0) {
    log.error('Sidecar', 'getRetType() can not get metadata.')
    log.error('Stack: %s', new Error().stack)
  }
  return methodTypeList
}

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

  updateRetType(
    target,
    propertyKey,
    [nativeType, ...pointerTypeList],
  )
}

export {
  getRetType,
  RET_TYPE_SYMBOL,
  RetType,
}
