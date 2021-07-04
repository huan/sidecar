import {
  log,
}                         from '../../config'

import {
  FridaTarget,
  LabelTarget,
}                 from '../../frida'

const HOOK_TARGET_SYMBOL = Symbol('hookTarget')

function updateMetadataHook (
  target      : Object,
  propertyKey : string,
  fridaTarget : FridaTarget | LabelTarget,
): void {
  // Update the parameter names
  Reflect.defineMetadata(
    HOOK_TARGET_SYMBOL,
    fridaTarget,
    target,
    propertyKey,
  )
}

function getMetadataHook (
  target      : Object,
  propertyKey : string,
): undefined | FridaTarget | LabelTarget {
  // Pull the array of parameter names
  const fridaTarget = Reflect.getMetadata(
    HOOK_TARGET_SYMBOL,
    target,
    propertyKey,
  )
  return fridaTarget
}

function Hook (
  fridaTarget: FridaTarget | LabelTarget,
) {
  log.verbose('Sidecar', '@Hook(%s)',
    typeof fridaTarget === 'object' ? JSON.stringify(fridaTarget)
      : typeof fridaTarget === 'number' ? fridaTarget.toString(16)
        : fridaTarget,
  )

  return function hookMethodDecorator (
    target      : Object,
    propertyKey : string,
    descriptor  : PropertyDescriptor,
  ): PropertyDescriptor {
    log.verbose('Sidecar',
      '@Hook(%s) hookMethodDecorator(%s, %s, descriptor)',
      typeof fridaTarget === 'object' ? JSON.stringify(fridaTarget)
        : typeof fridaTarget === 'number' ? fridaTarget.toString(16)
          : fridaTarget,

      target.constructor.name,
      propertyKey,
    )

    updateMetadataHook(
      target,
      propertyKey,
      fridaTarget,
    )

    // Huan(202106) TODO: add a replaced function to show a error message when be called.
    return descriptor
  }
}

export {
  Hook,
  getMetadataHook,
  HOOK_TARGET_SYMBOL,
}
