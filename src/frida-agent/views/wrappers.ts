import { SidecarFunctionDescription } from './sidecar-view'

function wrappedArgs (this: SidecarFunctionDescription) {
  const typeList = this.paramTypeList
  if (!typeList) {
    throw new Error('no .paramTypeList found in SidecarFunctionDescription!')
  }

  const wrappedArgList = []
  for (const [idx, typeChain] of typeList.entries()) {
    const [nativeType, ...pointerTypeList] = typeChain
    // console.log(nativeType, pointerTypeList)

    const readChain = [
      `args[${idx}]`,
    ]

    if (nativeType === 'pointer') {
      readChain.push('.readPointer()')
      for (const pointerType of pointerTypeList) {
        readChain.push(`.read${pointerType}()`)
      }
    }

    wrappedArgList.push(readChain.join(''))
  }

  return '[ ' + wrappedArgList.join(', ') + ' ]'
}

function wrappedRet (this: SidecarFunctionDescription) {
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
    readChain.push('.readPointer()')
    for (const pointerType of pointerTypeList) {
      readChain.push(`.read${pointerType}()`)
    }
  }

  return readChain.join('')
}

export {
  wrappedArgs,
  wrappedRet,
}
