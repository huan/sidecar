import { SidecarFunctionDescription } from '../agent/sidecar-view'

function nativeRetType (this: SidecarFunctionDescription) {
  // console.log('this.retType', this.retType)
  if (!this.retType || this.retType.length <= 0) {
    return "'void'"
  }
  return `'${this.retType[0]}'`
}

export { nativeRetType }
