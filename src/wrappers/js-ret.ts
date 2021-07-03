import { SidecarFunctionDescription } from '../agent/sidecar-view'

function jsRet (this: SidecarFunctionDescription) {
  const typeChain = this.retType
  if (!typeChain) {
    throw new Error('no .retType found in SidecarFunctionDescription context!')
  }

  const [nativeType, ...pointerTypeList] = typeChain
  // console.log(nativeType, pointerTypeList)

  const readChain = [
    'ret',
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

  return readChain.join('')
}

export { jsRet }
