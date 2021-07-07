import Mustache from  'mustache'

import { SidecarMetadata } from '../decorators/sidecar/metadata-sidecar'

import { wrapView }       from '../wrappers/mod'

import { log } from '../config'

import { partialLookup }  from './partial-lookup'

const AGENT_MUSTACHE = 'agent.mustache'

async function buildAgentSource (metadata: SidecarMetadata) {
  log.verbose('Sidecar', 'buildAgentSource()')
  log.silly('Sidecar', 'buildAgentSource(%s)', JSON.stringify(metadata))

  const agentMustache = partialLookup(AGENT_MUSTACHE)
  const view = wrapView(metadata)

  const source = await Mustache.render(
    agentMustache,
    view,
    partialLookup,
  )

  return source
}

export { buildAgentSource }
