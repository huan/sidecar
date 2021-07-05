log.setLevel(3)

const agentMo = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11c9),
  'void',
  ['pointer'],
)

const agentMt_NativeCallback = new NativeCallback(
  (...args) => {
    log.verbose('Agent()', 'agentMt() faint from Frida: %s', args[0].readUtf8String())
    // send(hookPayload(
    //   'mt',
    //   [ args[0].readUtf8String() ]
    // ), null)
  },
  'void',
  ['pointer'],
)

const agentMt_NativeFunction = new NativeFunction(
  agentMt_NativeCallback,
  'void',
  ['pointer'],
)

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x11f4),
  {
    onEnter: args => agentMt_NativeFunction(args[0]),
  }
)
