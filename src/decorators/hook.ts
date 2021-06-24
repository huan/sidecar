import {
  log,
}                         from '../config'

import {
  AgentFather,
}               from '../agent-father'
import { TargetType } from '../frida'

const agentFather = AgentFather.instance()

function Hook (
  target: TargetType,
) {
  return (
    target : any,
    key : string,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor => {
    return {} as any
  }
}

export { Hook }
