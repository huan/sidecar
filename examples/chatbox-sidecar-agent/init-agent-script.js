/**
 * Call -> moHelper(message)
 *  MO Sidecar Agent Helper
 */
const moJsFunction = (() => {
  /**
   * Huan(202107): We might need more code here, that's why we created a closure at here.
   */
  const moNativeFunction = new NativeFunction(
    __sidecar__moduleBaseAddress.add(0x11e9),
    'int',
    ['pointer'],
  )

  return function (content) {
    const buf = Memory.allocUtf8String(content)
    const ret = moNativeFunction(buf)
    return ret + 1
  }
})()

/**
 * Hook -> mtNativeCallback
 *  MT Sidecar Agent Helper
 */
const mtNativeCallback = (() => {
  const mtNativeCallback = new NativeCallback(() => {}, 'void', ['pointer'])
  const mtNativeFunction = new NativeFunction(mtNativeCallback, 'void', ['pointer'])

  Interceptor.attach(
    __sidecar__moduleBaseAddress.add(0x121f),
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

        /**
          * https://github.com/frida/frida/issues/1774#issuecomment-878173544
          *   Huan(20210713): it seems not work with `Interceptor.replace` too?
          */
        // mtNativeFunction(args[0])
      }
    }
  )
  return mtNativeCallback
})()
