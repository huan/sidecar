import { SidecarFunctionDescription } from '../agent/sidecar-view'

function nativeParamTypes (this: SidecarFunctionDescription) {
  /**
   * There's no any parameters
   */
  if (!this.paramTypeList) {
    return ''
  }
  return this.paramTypeList
    .map(paramType => `'${paramType[0]}'`)
    .join(', ')
}

export { nativeParamTypes }
