import { SidecarFunctionDescription } from '../sidecar-view'
import { nativeArgName } from './name-helpers'

function nativeArgs (this: SidecarFunctionDescription) {
  const name = this.name
  const paramTypeList = this.paramTypeList
  if (!Array.isArray(paramTypeList)) {
    throw new Error('Can not found .paramTypeList in SidecarFunctionDescription!')
  }

  const nativeArgNameList = []

  for (let i = 0; i < paramTypeList.length; i++) {
    nativeArgNameList.push(
      nativeArgName(name, i)
    )
  }

  return '[ ' + nativeArgNameList.join(', ') + ' ]'
}

export { nativeArgs }
