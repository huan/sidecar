#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import {
  getMetadataView,
  updateMetadataView,
}                         from './metadata-view'

test('update & get view metadata', async t => {
  const VALUE = getSidecarViewFixture()
  const TARGET = {}

  updateMetadataView(
    TARGET,
    VALUE,
  )

  const data = getMetadataView(
    TARGET,
  )

  t.deepEqual(data, VALUE, 'should get the view data the same as we set(update)')
})
