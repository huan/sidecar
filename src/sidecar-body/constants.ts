const DESTROY_SYMBOL = Symbol('destroy')
const INIT_SYMBOL    = Symbol('init')
const START_SYMBOL   = Symbol('start')
const STOP_SYMBOL    = Symbol('stop')

const EMIT_PAYLOAD_HANDLER_SYMBOL     = Symbol('emitPayloadHandler')
const SCRIPT_DESTROYED_HANDLER_SYMBOL = Symbol('scriptDestroyedHandler')
const SCRIPT_MESSAGRE_HANDLER_SYMBOL  = Symbol('scriptMessageHandler')
export {
  DESTROY_SYMBOL,
  INIT_SYMBOL,
  START_SYMBOL,
  STOP_SYMBOL,

  EMIT_PAYLOAD_HANDLER_SYMBOL,
  SCRIPT_DESTROYED_HANDLER_SYMBOL,
  SCRIPT_MESSAGRE_HANDLER_SYMBOL,
}
