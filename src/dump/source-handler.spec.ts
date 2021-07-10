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

  const normalize = (text: string) => text
    .replace(/\s+/sg, ' ')
    /**
     * For CI under Linux
     */
    .replace(/"[^"]+sidecar\/examples\/chatbox\/chatbox-linux"/sg, '"chatbox-linux"')
    /**
     * For CI under Windows
     *  D:\\a\\sidecar\\sidecar\\examples\\chatbox\\chatbox-win32.exe"
     */
    .replace(/"[^"]+sidecar\\examples\\chatbox\\chatbox-win32.exe"/sg, '"chatbot-win32.exe"')

  const EXPECTED = await fs
    .readFileSync(EXPECTED_FILE)
    .toString()

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
    normalize(source),
    normalize(EXPECTED),
    'should get the source from ts file',
  )
})
