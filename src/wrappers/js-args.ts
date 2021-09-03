import type { SidecarMetadataFunctionDescription } from '../decorators/mod.js'
import { argName } from './name-helpers.js'

function jsArgs (
  this: SidecarMetadataFunctionDescription
): string {
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
