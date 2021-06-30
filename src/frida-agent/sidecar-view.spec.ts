#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  sidecarView,
}                       from './sidecar-view'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'
import { getSidecarViewFixture }     from '../../tests/fixtures/sidecar-view.fixture'

test('sidecarView()', async t => {

  const SIDECAR_METADATA = getSidecarMetadataFixture()
  const SIDECAR_VIEW = getSidecarViewFixture()

  const view = sidecarView(SIDECAR_METADATA)
  // console.log(JSON.stringify(view, null, 2))
  t.deepEqual(view, SIDECAR_VIEW, 'should get the correct sidecar view for the metadata')
})
