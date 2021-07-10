#!/usr/bin/env ts-node
import { test }  from 'tstest'

import fs from 'fs'
import path from 'path'

import {
  extractClassNameListFromSource,
}                                   from './extract-class-names'

test('extractClassNameListFromSource()', async t => {
  const TS = `
  @Sidecar(
    targetProgram(),
    loadAgentSource(),
  )
  class ChatboxSidecar extends SidecarBody {}

  @Sidecar(
    targetProgram(),
    loadAgentSource(),
  )

  class ChatboxSidecar2 extends SidecarBody {}
  `
  const EXPECTED = ['ChatboxSidecar', 'ChatboxSidecar2']

  const classNameList = await extractClassNameListFromSource(TS)
  t.deepEqual(classNameList, EXPECTED, 'should extract the class name correct')
})

test('extractClassNameListFromSource() with export', async t => {
  const TS = `
  @Sidecar(
    targetProgram(),
    loadAgentSource(),
  )
  export class ChatboxSidecar extends SidecarBody {}
  `
  const EXPECTED = ['ChatboxSidecar']

  const classNameList = await extractClassNameListFromSource(TS)
  t.deepEqual(classNameList, EXPECTED, 'should extract the exported class name correct')
})

test('extractClassNameListFromSource() with examples/chatbox-sidebar.ts', async t => {
  const TS = await fs.readFileSync(path.join(
    __dirname,
    '..',
    '..',
    'examples',
    'chatbox-sidecar.ts',
  )).toString()

  const EXPECTED = ['ChatboxSidecar']

  const classNameList = await extractClassNameListFromSource(TS)
  t.deepEqual(classNameList, EXPECTED, 'should extract the class name correct')
})
