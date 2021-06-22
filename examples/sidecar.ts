import frida from 'frida'

const AGENT_SOURCE =
`
var MO_ADDR = ptr(0x102d2bddc)
var MT_ADDR = ptr(0x102d2be10)

var mo = new NativeFunction(
  MO_ADDR,
  'void',
  ['pointer'],
)

Interceptor.attach(
  MT_ADDR,
  {
    onEnter: args => {
      console.log('recv:', args[0].readUtf8String())
    }
  }
)

console.info('faint')
function init () {
  console.info('init')
}

export {
  init,
  mo,
}
`
async function main () {
  // const pid	=	frida.spawn(['/bin/ls'])
  const session	=	frida.attach('a.out')
  const script	=	session.create_script(AGENT_SOURCE)
  await script.load();

  script.exports.init()
  frida.resume(pid)

  script.rpc.sendMessage('test')
}

main()
.catch(console.error)
