const addressMessageBox = Module.findExportByName('user32.dll', 'MessageBoxW')!
if (!addressMessageBox) {
  throw new Error('no messageBox found')
}

function test (): void {

  const text = '中文'
  const textBuf = Memory.allocUtf16String(text)
  console.log('textBuf:', textBuf)
  console.log('textBuf:', textBuf.readUtf16String())
  console.log('addressMessageBox:', addressMessageBox)

  console.log(hexdump(textBuf, {
    offset: 0,
    length: 16,
    header: true,
    ansi: true,
  }))

  const implBox = Memory.alloc(Process.pageSize);

  Memory.patchCode(implBox, Process.pageSize, function (code) {
    var cw = new X86Writer(code, { pc: implBox })

    cw.putPushU32(1)
    cw.putPushU32(textBuf.toInt32())
    cw.putPushU32(textBuf.toInt32())
    cw.putPushU32(0)

    cw.putCallAddress(addressMessageBox)
    cw.putRet()

    cw.flush()
  })

  const testBox = new NativeFunction(implBox, 'uint', [])
  const ret = testBox()
  console.log('ret:', ret)
}
