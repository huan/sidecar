import Mustache from  'mustache'

import { SidecarMetadata } from '../decorators/sidecar/metadata-sidecar'

import { log } from '../config'

import { partialLookup } from './partial-lookup'
import { wrapView } from '../wrappers/mod'

const AGENT_MUSTACHE = 'agent.mustache'

interface BuildAgentSourceOptions {
  initAgentSource : string,
  metadata        : SidecarMetadata,
}

async function buildAgentSource (options: BuildAgentSourceOptions) {
  log.verbose('Sidecar', 'buildAgentSource()')
  log.silly('Sidecar', 'buildAgentSource(%s)', JSON.stringify(options))

  const agentMustache = partialLookup(AGENT_MUSTACHE)
  const view = wrapView(options.metadata)

  const source = await Mustache.render(
    agentMustache,
    view,
    partialLookup,
  )

  return source
}

export { buildAgentSource }
