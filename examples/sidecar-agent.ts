/**
 * Sidecar example agent
 *
 * Huan <zixia@zixia.net>, June 24, 2021
 *  https://github.com/huan/sidecar
 */
const MO_ADDR = ptr(0x55f06a55f1ba)
const MT_ADDR = ptr(0x55f06a55f1e5)

console.log('here')
const mo = new NativeFunction(
  MO_ADDR,
  'void',
  ['pointer'],
)

console.log('there')
// Interceptor.attach(
//   MT_ADDR,
//   {
//     onEnter: args => {
//       console.log('recv:', args[0].readUtf8String())
//     }
//   }
// )

console.log('faint')

function init () {
  console.log('init')
}

console.log('mo', mo)
console.log('mo addr', MO_ADDR)

rpc.exports = {
  init,
  mo,
}
