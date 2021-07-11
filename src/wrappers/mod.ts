import { SidecarMetadata } from '../decorators/sidecar/metadata-sidecar'

import { declareNativeArgs }      from './declare-native-args'
import { jsArgs }                 from './js-args'
import { jsRet }                  from './js-ret'
import { logLevel }               from './log-level'
import { moduleName }             from './module-name'
import { nativeArgs }             from './native-args'
import { nativeFunctionNameList } from './native-function-name-list'
import { nativeParamTypes }       from './native-param-types'
import { nativeRetType }          from './native-ret-type'
import { rawArgs }                from './raw-args'

const wrapView = (metadata: SidecarMetadata) => ({
  ...metadata,
  declareNativeArgs,
  jsArgs,
  jsRet,
  logLevel,
  moduleName,
  nativeArgs,
  nativeFunctionNameList,
  nativeParamTypes,
  nativeRetType,
  rawArgs,
})

export { wrapView }
