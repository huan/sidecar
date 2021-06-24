const rules = {
  'no-console': ['error', { allow: ['log', 'warn', 'error'] }],
}
const globals = {
  ptr: 'readonly',
  NativeFunction: 'readonly',
  rpc: 'readonly',
}

module.exports = {
  extends: '@chatie',
  rules,
  globals,
}
