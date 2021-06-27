import {
  FridaTarget,
  LabelTarget,
}                       from '../../frida'

import { CALL_TARGET_SYMBOL } from './constants'

function updateCallTarget (
  target      : Object,
  propertyKey : string | symbol,
  fridaTarget : FridaTarget | LabelTarget,
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    CALL_TARGET_SYMBOL,
    fridaTarget,
    target,
    propertyKey,
  )
}

function getCallTarget (
  target         : Object,
  propertyKey    : string | symbol,
): undefined | FridaTarget | LabelTarget {
  // Pull the array of parameter names
  const fridaTarget = Reflect.getMetadata(
    CALL_TARGET_SYMBOL,
    target,
    propertyKey,
  )
  return fridaTarget
}

export {
  updateCallTarget,
  getCallTarget,
}
