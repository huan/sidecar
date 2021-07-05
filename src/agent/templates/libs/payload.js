/********************************************
 * File: templates/lib/payload.js
 *
 * To make sure the payload typing is right
 * See: sidecar-body/payload-schema.ts
 ********************************************/
/**
 * SidecarBodyEventPayloadHook
 */
const hookPayload = (
  method, // string
  args,   // Arguments, Array
) => ({
  payload : {
    args,
    method,
  },
  type     : 'hook',
})

/**
 * SidecarBodyEventPayloadLog
 */
const logPayload = (
  payload,
) => ({
  payload,
  type : 'log',
})

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    hookPayload,
    logPayload,
  }
}
