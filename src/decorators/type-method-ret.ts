import {
  NativeType,
  PointerType,
}               from '../frida'
import {
  log,
}               from '../config'

const METHOD_RET_TYPE_SYMBOL = Symbol('methodRetType')

function updateMethodRetType (
  target         : Object,
  propertyKey    : string | symbol,
  typeList       : (NativeType | PointerType)[],
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    METHOD_RET_TYPE_SYMBOL,
    typeList,
    target,
    propertyKey,
  )
}

function getMethodRetType (
  target         : Object,
  propertyKey    : string | symbol,
): (NativeType | PointerType)[] {
  // Pull the array of parameter names
  const methodTypeList = Reflect.getMetadata(
    METHOD_RET_TYPE_SYMBOL,
    target,
    propertyKey,
  )
  if (!Array.isArray(methodTypeList) || methodTypeList.length <= 0) {
    log.error('Sidecar', 'type-method getMethodRetType() can not get metadata.')
    log.error('Stack: %s', new Error().stack)
  }
  return methodTypeList
}

const TypeMethodRet = (
  nativeType         : NativeType,
  ...pointerTypeList : PointerType[]
) => (
  target         : Object,
  propertyKey    : string | symbol,
  _descriptor     : PropertyDescriptor,
) => {
  log.verbose('Sidecar',
    'Type<MethodReturn>(%s, %s) => (%s, %s)',
    nativeType,
    pointerTypeList.join(','),
    target.constructor.name,
    propertyKey,
  )

  updateMethodRetType(
    target,
    propertyKey,
    [nativeType, ...pointerTypeList],
  )
}

export {
  getMethodRetType,
  METHOD_RET_TYPE_SYMBOL,
  TypeMethodRet,
}
