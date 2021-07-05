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
  type     : 'hook',
  papyload : {
    method,
    args,
  }
})

/**
 * SidecarBodyEventPayloadLog
 */
const logPayload = (
  payload,
) => ({
  type : 'log',
  payload,
})
