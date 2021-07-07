import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import { SidecarBodyEventPayloadHook } from './payload-schemas'

// import {
//   SidecarBodyEventPayloadLog,
//   SidecarBodyEventPayloadHook,
// }                               from './payload-schemas'

// export type AttachedEventListener = () => void
// export type DetachedEventListener = () => void
// export type InitedEventListener   = () => void

// export type HookEventListener = (payload: SidecarBodyEventPayloadHook['payload']) => void
// export type LogEventListener  = (payload: SidecarBodyEventPayloadLog['payload'])  => void

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
  args: Error | SidecarBodyEventPayloadHook['payload']['args']
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
