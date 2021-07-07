import { SidecarMetadataFunctionDescription } from '../decorators/mod'
import { nativeArgName } from './name-helpers'

function nativeArgs (
  this: SidecarMetadataFunctionDescription,
): string {
  const name = this.name
  const paramTypeList = this.paramTypeList

  /**
   * There's no any parameters needed
   */
  if (!Array.isArray(paramTypeList)) {
    return '[]'
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
