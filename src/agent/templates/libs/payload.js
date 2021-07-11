/********************************************
 * File: templates/lib/payload.js
 *
 * To make sure the payload typing is right
 * See: sidecar-body/payload-schema.ts
 ********************************************/
/**
 * SidecarPayloadHook
 */
const sidecarPayloadHook = (
  method, // string
  args,   // Arguments, Array
) => ({
  payload: {
    args,
    method,
  },
  type: 'hook',
})

/**
 * SidecarPayloadLog
 */
const sidecarPayloadLog = (
  level,    // verbose, silly
  prefix,   // module name
  message,  // string
) => ({
  payload: {
    level,
    message,
    prefix,
  },
  type : 'log',
})

/**
 * For unit testing under Node.js
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    sidecarPayloadHook,
    sidecarPayloadLog,
  }
}
