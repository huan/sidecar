import { SidecarMetadata } from '../decorators/sidecar/metadata-sidecar'

import { declareNativeArgs }      from './declare-native-args'
import { jsArgs }                 from './js-args'
import { jsRet }                  from './js-ret'
import { moduleName }             from './module-name'
import { nativeArgs }             from './native-args'
import { nativeFunctionNameList } from './native-function-name-list'
import { nativeParamTypes }       from './native-param-types'
import { nativeRetType }          from './native-ret-type'

const wrapView = (metadata: SidecarMetadata) => ({
  ...metadata,
  declareNativeArgs,
  jsArgs,
  jsRet,
  moduleName,
  nativeArgs,
  nativeFunctionNameList,
  nativeParamTypes,
  nativeRetType,
})

export { wrapView }
