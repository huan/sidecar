import { EventEmitter } from 'stream'
import type TypedEventEmitter  from 'typed-emitter'

import type { SidecarPayloadHook } from './payload-schemas.js'

// import {
//   SidecarPayloadLog,
//   SidecarPayloadHook,
// }                               from './payload-schemas.js'

// export type AttachedEventListener = () => void
// export type DetachedEventListener = () => void
// export type InitedEventListener   = () => void

// export type HookEventListener = (payload: SidecarPayloadHook['payload']) => void
// export type LogEventListener  = (payload: SidecarPayloadLog['payload'])  => void

// interface SidecarEvents {
//   attached : AttachedEventListener
//   detached : DetachedEventListener
//   error    : Error
//   hook     : HookEventListener
//   inited   : InitedEventListener
//   log      : LogEventListener
// }

export type SymbolEventListener = () => void
export type HookEventListener   = (
  args: Error | SidecarPayloadHook['payload']['args']
) => void

interface SidecarEvents {
  [symbol: symbol]: SymbolEventListener
  [hook: string]: HookEventListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>

const SidecarEmitter = EventEmitter as SidecarEmitterType

export { SidecarEmitter }
