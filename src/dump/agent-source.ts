// import vm from 'vm'

import {
  command,
  number,
  option,
  positional,
  string,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'

// import { sidecarView } from '../frida-agent/sidecar-view'

// import { transpileTsSourceFile } from './transpile-ts-source'

/* eslint-disable sort-keys */

const agentSource = command({
  name: 'agent-source',
  description: 'Sidecar dumping agent source',
  args: {
    file: positional({ type: File, displayName: 'decorated class file' }),
    name: option({ type: string, long: 'name' }),
    age: option({ type: number, long: 'age' }),

  },
  handler: (args) => {
    console.log('agentSource: ', args.file, args.name, args.age)
  },
})

export { agentSource }
