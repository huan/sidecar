import {
  log,
}                         from './config'

import {
  TargetType,
  NativeType,
  PointerType,
}               from '../frida'

// interface CallOptions {
//   retType: NativeType,
//   argTypes: NativeType[],
//   abi: NativeABI,
// }

function Call (
  target: TargetType,
  nativeType: NativeType,
  ...pointerTypeChain: (undefined | PointerType)[]
) {
  return (
    target : any,
    key : string,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor => {
    return {} as any
  }
}

export { Call }
