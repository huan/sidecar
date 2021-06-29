/**
 * To make sure the payload typing is right
 */
const hookPayload = (
  method, // string
  args,   // Arguments, Array
) => ({
  type: 'hook',
  method,
  args,
})

const logPayload = (
  message,
) => ({
  type: 'log',
  message,
})
