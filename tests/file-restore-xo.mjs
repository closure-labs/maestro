import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { basename, dirname } from 'node:path'

const [root, disk] = process.argv.slice(2)
const require = createRequire(root + '/package.json')
const { default: Disposable } = await import(require.resolve('promise-toolbox/Disposable'))
const { fileRestoreMethods } = await import(root + '/@xen-orchestra/backups/_fileRestore.mjs')
const { getHandler } = require('@xen-orchestra/fs')
const handler = getHandler({ url: 'file://' + dirname(disk) })
await handler.sync()
let active = 0
const adapter = {
  _handler: handler,
  getDisk: Disposable.factory(async function* (diskId) {
    active++
    try { yield* fileRestoreMethods.getDisk.call(this, diskId) } finally { active-- }
  }),
  _getPartition() { throw new Error('legacy host mount must not execute') },
  _getLvmPhysicalVolume() { throw new Error('legacy host LVM must not execute') },
  _listLvmLogicalVolumes() { throw new Error('legacy host LVM must not execute') },
}
const diskId = basename(disk)
const partitions = await fileRestoreMethods.listPartitions.call(adapter, diskId)
await assert.rejects(fileRestoreMethods.getPartition.call(adapter, 'fixture', '/dev/sda1').next(), /host partition mounting is disabled/)
assert.equal(partitions.length, 1)
const id = partitions[0].id
assert.deepEqual(await fileRestoreMethods.listPartitionFiles.call(adapter, diskId, id, '/docs'), { sentinel: {} })
for (const format of ['tgz', 'zip']) {
  const stream = await fileRestoreMethods.fetchPartitionFiles.call(adapter, diskId, id, ['/docs'], format)
  let size = 0
  for await (const chunk of stream) size += chunk.length
  assert(size > 20)
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(active, 0)
}
console.log('installed XO listing and streamed archive APIs use the isolated helper')
await handler.forget()
