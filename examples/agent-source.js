const agentMo = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11c9),
  'void',
  ['pointer'],
)

const agentMt_PatchCode = Memory.alloc(Process.pageSize)

// Memory.patchCode(agentMt_PatchCode, Process.pageSize, function (code) {
//   var cw = new X86Writer(code, { pc: agentMt_PatchCode })
//   cw.putNop()
//   cw.putNop()
//   cw.putNop()
//   cw.putNop()
//   cw.putRet()
//   cw.flush()
// })

// const agentMt_NativeCallback = new NativeCallback(
//   (...args) => {
//     log.verbose('FridaAgent', 'agentMt() faint from Frida: %s', args[0].readUtf8String())
//     send(hookPayload(
//       'mt',
//       {
//         ...[args[0].readUtf8String()],
//         // Huan(202107): TODO: add name alias support
//       }
//     ), null)
//   },
//   'void',
//   ['pointer'],
// )

// const agentMt_NativeFunction = new NativeFunction(
//   // agentMt_NativeCallback,
//   agentMt_PatchCode,
//   'void',
//   ['pointer'],
// )

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x11f4),
  {
    onEnter: args => {
      console.log('interceptor called', args[0].readUtf8String())
      send(hookPayload({
        type: 'hook',
        payload: {
          method: 'mt',
          args: {
            content: args[0].readUtf8String(),
          },
        },
      }))
    } // agentMt_NativeFunction(args[0]),
  }
)
