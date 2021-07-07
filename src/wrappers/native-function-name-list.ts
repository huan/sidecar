import { SidecarMetadata } from '../decorators/sidecar/mod'

function nativeFunctionNameList (this: SidecarMetadata) {
  return this.nativeFunctionList
    .map(x => Object.values(x))
    .flat()
    .map(x => x.name)
}

export { nativeFunctionNameList }
