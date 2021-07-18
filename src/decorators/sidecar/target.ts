import { spawn } from 'child_process'
import { TargetProcess } from 'frida'

type SpawnParameters = Parameters<typeof spawn>
export type SidecarTargetRawSpawn = [
  command : SpawnParameters[0],
  args?   : SpawnParameters[1],
]
export type SidecarTargetRaw =  TargetProcess
                              | SidecarTargetRawSpawn

interface SidecarTargetObjProcess {
  type: 'process',
  target: TargetProcess
}
export interface SidecarTargetObjSpawn {
  type: 'spawn',
  target: SidecarTargetRawSpawn,
}
export type SidecarTargetObj =  SidecarTargetObjProcess
                              | SidecarTargetObjSpawn

export type SidecarTarget = SidecarTargetRaw
                          | SidecarTargetObj

const sidecarTargetObjProcess = (target: TargetProcess) => ({
  target,
  type: 'process',
}) as SidecarTargetObjProcess

const sidecarTargetObjSpawn = (target: SidecarTargetRawSpawn) => ({
  target,
  type: 'spawn',
}) as SidecarTargetObjSpawn

const normalizeSidecarTarget = (
  target?: SidecarTarget,
): undefined | SidecarTargetObj => {
  if (typeof target === 'string' || typeof target === 'number') {
    return sidecarTargetObjProcess(target)
  } else if (Array.isArray(target)) {
    return sidecarTargetObjSpawn(target)
  } else {
    return target
  }
}

const isSidecarTargetProcess  = (target?: SidecarTarget): target is SidecarTargetObjProcess  => typeof target === 'object' && !Array.isArray(target) && target.type === 'process'
const isSidecarTargetSpawn    = (target?: SidecarTarget): target is SidecarTargetObjSpawn    => typeof target === 'object' && !Array.isArray(target) && target.type === 'spawn'

export {
  normalizeSidecarTarget,
  isSidecarTargetProcess,
  isSidecarTargetSpawn,
}
