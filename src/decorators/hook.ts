import {
  log,
}                         from '../config'

import { FridaTarget } from '../frida'

function Hook (
  target: FridaTarget,
) {
  return (
    target : any,
    key : string,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor => {
    return {} as any
  }
}

export { Hook }
