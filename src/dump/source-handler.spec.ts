#!/usr/bin/env ts-node
import { test }  from 'tstest'

import fs from 'fs'
import path from 'path'

import {
  sourceHandler,
}                                   from './source-handler'

test('sourceHandler()', async t => {
  const FILE = path.join(
    __dirname,
    '..',
    '..',
    'examples',
    'chatbox-sidecar.ts',
  )
  const EXPECTED_FILE = path.join(
    __dirname,
    '..',
    '..',
    'tests',
    'fixtures',
    'chatbox-sidecar.source.js',
  )

  const EXPECTED = await fs.promises.readFile(EXPECTED_FILE)
  const source = await sourceHandler({ file: FILE })

  /**
   * Generate the testing fixture file, Huan(202107)
   *
   *  When we have updated the examples/chatbox-sidecar.ts file,
   *  we need to update the `tests/fixtures/chatbox-sidecar.source.js`
   *  so that the unit testing can be match the updated frida agent source code.
   */
  // fs.writeFileSync('t.js', source)

  /**
   * We remove all spaces in the file so that the comparision will ignore all spaces
   */
  t.equal(
    source.replace(/\s+/sg, ' '),
    EXPECTED.toString().replace(/\s+/sg, ' '),
    'should get the source from ts file',
  )
})
