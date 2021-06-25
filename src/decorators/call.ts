import {
  log,
}                         from '../config'

import {
  FridaTarget,
  LabelTarget,
}                 from '../frida'

const CALL_TARGET_SYMBOL = Symbol('Call')

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

const Call = (
  fridaTarget: FridaTarget | LabelTarget,
) => (
  target      : Object,
  propertyKey : string | symbol,
  descriptor  : PropertyDescriptor,
): PropertyDescriptor => {
  log.verbose('Sidecar',
    'Call(%s) => (%s, %s)',
    fridaTarget,
    target.constructor.name,
    propertyKey,
  )

  updateCallTarget(
    target,
    propertyKey,
    fridaTarget,
  )

  // Huan(202106) TODO: add a replaced function to show a error message when be called.
  return descriptor
}

export {
  Call,
  getCallTarget,
  CALL_TARGET_SYMBOL,
}
