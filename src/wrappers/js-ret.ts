import { log } from '../config'
import { SidecarMetadataFunctionDescription } from '../decorators/mod'

function jsRet (this: SidecarMetadataFunctionDescription) {
  const typeChain = this.retType
  if (!typeChain) {
    throw new Error('no .retType found in SidecarMetadataFunctionDescription context!')
  }

  const [nativeType, ...pointerTypeList] = typeChain
  // console.log(nativeType, pointerTypeList)

  const resultChain = []

  if (nativeType === 'pointer') {
    if (pointerTypeList.length > 0) {
      resultChain.push(
        'ret.readPointer()'
      )
      for (const pointerType of pointerTypeList) {
        resultChain.push(
          `.read${pointerType}()`
        )
      }
    } else {
      resultChain.push('ret') // raw pointer
    }
  } else {
    switch (nativeType) {
      case 'bool':
        log.silly('Sidecar', 'wrappers/js-ret NativeType(bool) for ret')
        resultChain.push('Boolean(ret)')
        break
      case 'void':
        log.silly('Sidecar', 'wrappers/js-ret NativeType(void) for ret')
        break
      default:  // all number types
        log.silly('Sidecar', 'wrappers/js-ret NativeType(number<%s>) for ret', nativeType)
        resultChain.push('Number(ret)')
        break
    }
  }

  return resultChain.join('')
}

export { jsRet }
