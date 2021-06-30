import { SidecarFunctionDescription } from '../sidecar-view'

function nativeRetType (this: SidecarFunctionDescription) {
  if (!this.retType) {
    throw new Error('no .retType found in SidecarFunctionDescription!')
  }
  return `'${this.retType[0]}'`
}

export { nativeRetType }
