import { SidecarFunctionDescription } from '../sidecar-view'

import {
  argName,
  bufName,
  nativeArgName,
}                 from './name-helpers'

function declareNativeArgs (this: SidecarFunctionDescription) {
  const name          = this.name
  const paramTypeList = this.paramTypeList
  if (!Array.isArray(paramTypeList)) {
    throw new Error('Can not found .paramTypeList in SidecarFunctionDescription!')
  }

  const declareStatementList = []
  for (const [argIdx, paramTypeChain] of paramTypeList.entries()) {
    const [nativeType, ...pointerTypeList] = paramTypeChain
    // console.log(argIdx, nativeType, pointerTypeList)

    const statementChain = []

    if (nativeType !== 'pointer') {
      statementChain.push(
        '',
        `// non-pointer type for arg[${argIdx}]: ${nativeType}`,
        `const ${nativeArgName(name, argIdx)} = ${argName(argIdx)}`,
      )
      declareStatementList.push(statementChain.join('\n  '))
      continue
    }

    statementChain.push(
      '',
      `// pointer type for arg[${argIdx}] -> ${pointerTypeList.join(' -> ')}`,
      `const ${nativeArgName(name, argIdx)} = Memory.alloc(Process.pointerSize)`,
    )

    let lastVarName: string = nativeArgName(name, argIdx)
    for (const [typeIdx, pointerType] of pointerTypeList.entries()) {
      if (pointerType === 'Pointer') {
        statementChain.push(
          '',
          `const ${bufName(name, argIdx, typeIdx)} = Memory.alloc(Process.pointerSize)`,
          `${lastVarName}.writePointer(${bufName(name, argIdx, typeIdx)})`
        )
        lastVarName = bufName(name, argIdx, typeIdx)
      } else {
        statementChain.push(
          '',
          `${lastVarName}.write${pointerType}(${argName(argIdx)})`,
        )
      }
    }

    declareStatementList.push(statementChain.join('\n  '))
  }

  return declareStatementList.join('\n\n')
}

export { declareNativeArgs }
