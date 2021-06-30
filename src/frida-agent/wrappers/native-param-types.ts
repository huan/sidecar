import { SidecarFunctionDescription } from '../sidecar-view'

function nativeParamTypes (this: SidecarFunctionDescription) {
  if (!this.paramTypeList) {
    throw new Error('.paramTypeList not found in SidecarFunctionDescription!')
  }
  return this.paramTypeList
    .map(paramType => `'${paramType[0]}'`)
    .join(', ')
}

export { nativeParamTypes }
