import { SidecarPayloadHook } from './sidecar-body/payload-schemas'

/**
 * `args` at here is a Array, which is the arguments of the hooked function
 *  It will be transformed to a Object internally
 */
declare const sidecarPayloadHook = (method: string, args: any[]) => SidecarPayloadHook

/**
 * declared in templates/agent.mustache
 */
declare const sidecarModuleBaseAddress: NativePointer
