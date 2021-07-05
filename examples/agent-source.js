const agentMo = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11c9),
  'void',
  ['pointer'],
)

const agentMt = new NativeCallback(
  () => { console.log('faint') },
  'void',
  ['pointer'],
)
const agentMtProxy = new NativeFunction(
  agentMt,
  'void',
  ['pointer'],
)

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x11f4),
  {
    onEnter: args => agentMtProxy(args[0]),
  }
)
