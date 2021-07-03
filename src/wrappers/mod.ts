import { SidecarView } from '../agent/sidecar-view'

import { declareNativeArgs } from './declare-native-args'
import { hexAddress } from './hex-address'
import { jsArgs } from './js-args'
import { jsRet } from './js-ret'
import { moduleName } from './module-name'
import { nativeArgs } from './native-args'
import { nativeParamTypes } from './native-param-types'
import { nativeRetType } from './native-ret-type'

const wrapView = (view: SidecarView) => ({
  ...view,
  declareNativeArgs,
  hexAddress,
  jsArgs,
  jsRet,
  moduleName,
  nativeArgs,
  nativeParamTypes,
  nativeRetType,
})

export { wrapView }
