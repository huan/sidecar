import {
  log,
}                         from '../config'

import { FridaTarget } from '../frida'

const HOOK_TARGET_SYMBOL = Symbol('hookTarget')

function updateHookTarget (
  target      : Object,
  propertyKey : string | symbol,
  fridaTarget : FridaTarget,
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    HOOK_TARGET_SYMBOL,
    fridaTarget,
    target,
    propertyKey,
  )
}

function getHookTarget (
  target         : Object,
  propertyKey    : string | symbol,
): undefined | FridaTarget {
  // Pull the array of parameter names
  const fridaTarget = Reflect.getMetadata(
    HOOK_TARGET_SYMBOL,
    target,
    propertyKey,
  )
  return fridaTarget
}

const Hook = (
  fridaTarget: FridaTarget,
) => (
  target      : Object,
  propertyKey : string | symbol,
  descriptor  : PropertyDescriptor,
): PropertyDescriptor => {
  log.verbose('Sidecar',
    'Hook(%s) => (%s, %s)',
    fridaTarget,
    target.constructor.name,
    propertyKey,
  )

  updateHookTarget(
    target,
    propertyKey,
    fridaTarget,
  )

  // Huan(202106) TODO: add a replaced function to show a error message when be called.
  return descriptor
}

export {
  Hook,
  getHookTarget,
  HOOK_TARGET_SYMBOL,
}
