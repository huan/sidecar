const rules = {
  'no-console': ['error', { allow: ['log', 'warn', 'error'] }],
  'multiline-ternary': 0,
}
const globals = {
  Interceptor: true,
  Memory: true,
  NativeFunction: true,
  ptr: true,
  rpc: true,
  send: true,
  recv: true,
}

module.exports = {
  extends: '@chatie',
  rules,
  globals,
}
