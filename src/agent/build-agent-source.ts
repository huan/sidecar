import Mustache from  'mustache'

import { log } from '../config'

import { partialLookup } from './partial-lookup'
import { SidecarView } from './sidecar-view'
import { wrapView } from '../wrappers/mod'

const AGENT_MUSTACHE = 'agent.mustache'

interface BuildAgentSourceOptions {
  initAgentSource : string,
  view            : SidecarView,
}

async function buildAgentSource (options: BuildAgentSourceOptions) {
  log.verbose('Sidecar', 'buildAgentSource()')
  log.silly('Sidecar', 'buildAgentSource(%s)', JSON.stringify(options))

  const agentMustache = partialLookup(AGENT_MUSTACHE)
  const agentView = {
    ...wrapView(options.view),
    initAgentSource: options.initAgentSource || '',
  }

  const source = await Mustache.render(
    agentMustache,
    agentView,
    partialLookup,
  )

  return source
}

export { buildAgentSource }
