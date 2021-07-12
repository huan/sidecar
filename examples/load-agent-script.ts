import fs   from 'fs'

function loadAgentScript () {
  const file = require.resolve('./init-agent-script.js')
  return fs.readFileSync(file, 'utf8')
}

export { loadAgentScript }
