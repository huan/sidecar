/**
 * Data Type:
 *  https://en.wikipedia.org/wiki/Data_type
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wizardsoftheweb.pro/typescript-decorators-parameter-decorators/
 */
import {
  NativeType,
  PointerType,
}               from '../frida'

import {
  getMethodRetType,
  TypeMethodRet,
}                     from './type-method-ret'
import {
  getParameterType,
  TypeParameter,
}                     from './type-parameter'

/**
 * Huan(202106)L
 *  `Type` supports both decorating `method` and `parameters`.
 */
const Type = (
  nativeType: NativeType,
  ...pointerTypeList: PointerType[]
) => (
  target            : Object,
  propertyKey       : string | symbol,
  indexOrDescriptor : number | PropertyDescriptor,
) => {
  let TypeDecorator: Function
  if (typeof indexOrDescriptor === 'number') {
    TypeDecorator = TypeParameter
  } else {
    TypeDecorator = TypeMethodRet
  }

  return TypeDecorator(
    nativeType,
    ...pointerTypeList,
  )(
    target,
    propertyKey,
    indexOrDescriptor,
  )
}

export {
  getMethodRetType,
  getParameterType,
  Type,
}
