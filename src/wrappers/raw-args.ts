import { SidecarMetadataFunctionDescription } from '../decorators/mod'
import { argName } from './name-helpers'

function rawArgs (this: SidecarMetadataFunctionDescription) {
  const typeList = this.paramTypeList
  if (!typeList) {
    throw new Error('no .paramTypeList found in SidecarMetadataFunctionDescription!')
  }

  const rawArgList = []

  for (const [idx, _] of typeList.entries()) {
    rawArgList.push(argName(idx))
  }

  return '[ ' + rawArgList.join(', ') + ' ]'
}

export { rawArgs }
