import fs from 'fs'

const AGENT_MUSTACHE_FILE = './agent.mustache'

async function loadAgentMustache () {
  const buf = await fs.promises.readFile(
    require.resolve(AGENT_MUSTACHE_FILE)
  )
  return buf.toString()
}

export { loadAgentMustache }
