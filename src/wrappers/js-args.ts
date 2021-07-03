import { SidecarMetadataFunctionDescription } from '../decorators/mod'
import { argName } from './name-helpers'

function jsArgs (this: SidecarMetadataFunctionDescription) {
  const typeList = this.paramTypeList
  if (!typeList) {
    throw new Error('no .paramTypeList found in SidecarMetadataFunctionDescription!')
  }

  const wrappedArgList = []
  for (const [idx, typeChain] of typeList.entries()) {
    const [nativeType, ...pointerTypeList] = typeChain
    // console.log(nativeType, pointerTypeList)

    const readChain = [
      argName(idx),
    ]

    /**
     * 1. native pointer
     */
    if (nativeType === 'pointer') {
      for (const pointerType of pointerTypeList) {
        readChain.push(
          `.read${pointerType}()`
        )
      }
    }

    wrappedArgList.push(readChain.join(''))
  }

  return '[ ' + wrappedArgList.join(', ') + ' ]'
}

export { jsArgs }
