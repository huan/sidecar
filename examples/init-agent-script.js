/**
 * Call -> moHelper(message)
 *  MO Sidecar Agent Helper
 */
const moNativeFunction = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11e9),
  'int',
  ['pointer'],
)

function moHelper (message) {
  const buf = Memory.allocUtf8String(message)
  return moNativeFunction(buf)
}

/**
 * Hook -> mtNativeCallback
 *  MT Sidecar Agent Helper
 */
const mtNativeCallback = new NativeCallback(() => {}, 'void', ['pointer'])
const mtNativeFunction = new NativeFunction(mtNativeCallback, 'void', ['pointer'])

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x121f),
  {
    onEnter: args => {
      log.verbose('AgentScript',
        'Interceptor.attach() onEnter() arg0: %s',
        args[0].readUtf8String(),
      )
      /**
       * Huan(202107):
       *  1. We MUST use `setImmediate()` for calling `mtNativeFunction(arg0),
       *    or the hook to mtNativeCallback will not be triggered. (???)
       *  2. `args` MUST be saved to arg0 so that it can be access in the `setImmediate`
       */
      const arg0 = args[0]
      setImmediate(() => mtNativeFunction(arg0))
    }
  }
)
