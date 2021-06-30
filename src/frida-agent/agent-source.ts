import Mustache from  'mustache'

import { log } from '../config'

import { partialLookup } from './partial-lookup'
import { SidecarView } from './sidecar-view'

const AGENT_MUSTACHE = 'agent.mustache'

interface AgentSourceOptions {
  initAgentSource : string,
  view            : SidecarView,
}

async function agentSource (options: AgentSourceOptions) {
  log.verbose('Sidecar', 'agentSource()')
  log.silly('Sidecar', 'agrentSource(%s)', JSON.stringify(options))

  const agentMustache = partialLookup(AGENT_MUSTACHE)

  const source = await Mustache.render(
    agentMustache,
    {
      ...options.view,
      initAgentSource: options.initAgentSource,
    },
    partialLookup,
  )

  return source
}

export { agentSource }
