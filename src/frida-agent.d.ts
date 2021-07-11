import { SidecarPayloadHook } from './sidecar-body/payload-schemas'

declare const sidecarPayloadHook = (method: string, args: {}) => SidecarPayloadHook

/**
 * declared in templates/agent.mustache
 */
declare const sidecarModuleBaseAddress: NativePointer
