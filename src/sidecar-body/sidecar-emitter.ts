import { EventEmitter } from 'events'
import type TypedEventEmitter  from 'typed-emitter'

import type {
  ATTACH_SYMBOL,
  DETACH_SYMBOL,
  INIT_SYMBOL,
}                       from './constants.js'
import type {
  SidecarPayloadHook,
  SidecarPayloadLog,
}                       from './payload-schemas.js'

type AttachedEventListener = () => void
type DetachedEventListener = () => void
type InitedEventListener   = () => void

type ErrorEventListener  = (e: Error) => void | Promise<void>
type HookEventListener   = (payload: SidecarPayloadHook['payload']) => void | Promise<void>
type LogEventListener    = (payload: SidecarPayloadLog['payload'])  => void | Promise<void>

interface SidecarEvents {
  [ATTACH_SYMBOL] : AttachedEventListener
  [DETACH_SYMBOL] : DetachedEventListener
  [INIT_SYMBOL]   : InitedEventListener

  error : ErrorEventListener
  hook  : HookEventListener
  log   : LogEventListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>

const SidecarEmitter = EventEmitter as any as SidecarEmitterType

export { SidecarEmitter }
