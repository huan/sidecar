import { SidecarMetadataFunctionDescription } from '../decorators/mod'

function nativeParamTypes (this: SidecarMetadataFunctionDescription) {
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
