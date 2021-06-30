import { SidecarFunctionDescription } from '../sidecar-view'
import { argName } from './name-helpers'

function jsArgs (this: SidecarFunctionDescription) {
  const typeList = this.paramTypeList
  if (!typeList) {
    throw new Error('no .paramTypeList found in SidecarFunctionDescription!')
  }

  const wrappedArgList = []
  for (const [idx, typeChain] of typeList.entries()) {
    const [nativeType, ...pointerTypeList] = typeChain
    // console.log(nativeType, pointerTypeList)

    const readChain = [
      argName(idx),
    ]

    if (nativeType === 'pointer') {
      readChain.push(
        '.readPointer()'
      )
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
