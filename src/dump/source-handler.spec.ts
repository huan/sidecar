#!/usr/bin/env ts-node
import { test }  from 'tstest'

import fs from 'fs'
import path from 'path'

import {
  sourceHandler,
}                                   from './source-handler'

test('sourceHandler()', async t => {
  const CLASS_FILE = path.join(
    __dirname,
    '..',
    '..',
    'examples',
    'chatbox-sidecar.ts',
  )
  const FIXTURE_FILE = path.join(
    __dirname,
    '..',
    '..',
    'tests',
    'fixtures',
    'chatbox-sidecar.source.js',
  )

  const normalize = (text: string) => text
    /**
     * Strip file path line for CI under Linux & Windows
     */
    .replace(/^.*chatbox.*$/gm, '')
    .replace(/[^\S\r\n]+/g, ' ')
    .replace(/^ +$/gm, '')  // remove spaces in empty line
    .replace(/\r/g, '')     // Windows will add \r, which need to be removed for comparing

  const FIXTURE = await fs
    .readFileSync(FIXTURE_FILE)
    .toString()

  const source = await sourceHandler({ file: CLASS_FILE })

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
  const normalizedSource = normalize(source)
  const normalizedFixture = normalize(FIXTURE)

  void normalizedSource
  void normalizedFixture
  // console.log('normalizedSource:', normalizedSource)
  // console.log('####################')
  // console.log('normalizedFixture:', normalizedFixture)
  // t.ok('oa')
  // console.log('###:', normalizedSource.length)

  t.equal(
    normalizedSource,
    normalizedFixture,
    'should get the source from ts file',
  )
})
