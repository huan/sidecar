/**
 * Data Type:
 *  https://en.wikipedia.org/wiki/Data_type
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wizardsoftheweb.pro/typescript-decorators-parameter-decorators/
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wotw.pro/typescript-decorators-parameter-decorators/
 */
import { log } from '../config'

const PARAMETER_NAME_SYMBOL = Symbol('parameterName')

/**
 * Credit: https://blog.wotw.pro/typescript-decorators-parameter-decorators/
 */
function setParameterNames (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
  name           : string,
) {
  // Pull the array of parameter names
  const parameterNameList = Reflect.getOwnMetadata(
    PARAMETER_NAME_SYMBOL,
    target,
    propertyKey,
  ) || []
  // Add the current parameter name
  parameterNameList[parameterIndex] = name
  // Update the parameter names
  Reflect.defineMetadata(
    PARAMETER_NAME_SYMBOL,
    parameterNameList,
    target,
    propertyKey,
  )
}

function getParameterNames (
  target         : Object,
  propertyKey    : string | symbol,
  parameterIndex : number,
) {
  // Pull the array of parameter names
  const parameterNameList = Reflect.getMetadata(
    PARAMETER_NAME_SYMBOL,
    target,
    propertyKey,
  ) || []
  return parameterNameList[parameterIndex]
}

const Name = (parameterName: string) => (
  target         : any,
  propertyKey    : string | symbol,
  parameterIndex : number,
) => {
  // console.log('isInstance:', isInstance(target))
  log.verbose('Sidecar',
    'Name(%s) => (%s, %s, %s)',
    parameterName,
    target.constructor.name,
    propertyKey,
    parameterIndex,
  )

  setParameterNames(
    target,
    propertyKey,
    parameterIndex,
    parameterName,
  )
}

export {
  getParameterNames,
  Name,
  PARAMETER_NAME_SYMBOL,
}
