import * as frida from 'frida'

const INJECT_SOURCE = `
  console.log('faint')
  const init = () => console.log('init')
  rpc.exports = {
    init
  }
`
async function main () {
  const pid = await frida.spawn(['/bin/ls'])
  const session = await frida.attach(pid)
  const script = await session.createScript(INJECT_SOURCE)
  await script.load()
  // eslint-disable-next-line no-console
  // console.log(script.exports)
  await script.exports.init()
  await frida.resume(pid)
}

main()
  .catch(console.error)
