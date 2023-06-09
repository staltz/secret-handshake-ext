const tape = require('tape')
const cl = require('chloride')
const base58 = require('bs58')
const shsePlugin = require('../lib/multiserver-plugin')

function hash(str) {
  return cl.crypto_hash_sha256(Buffer.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const appKey = hash('app_key')

tape('multiserver-plugin name and create', (t) => {
  const plugin = shsePlugin({ keys: alice, appKey, timeout: 10e3 })

  t.equals(plugin.name, 'shse')
  t.equals(typeof plugin.create, 'function')
  t.end()
})

tape('multiserver-plugin stringify', (t) => {
  const plugin = shsePlugin({ keys: alice, appKey, timeout: 10e3 })
  t.equals(
    plugin.stringify(),
    `shse:${base58.encode(alice.publicKey)}`,
    'plugin stringify'
  )
  t.end()
})

tape('multiserver-plugin parse', (t) => {
  const plugin = shsePlugin({ keys: alice, appKey, timeout: 10e3 })

  const buf1 = hash('foo')
  const buf2 = hash('bar')
  const pubkey = base58.encode(buf1)
  const extra = base58.encode(buf2)

  t.deepEquals(
    plugin.parse(`shse:${pubkey}`),
    { pubkey: buf1, extra: null },
    'parse just pubkey'
  )
  t.deepEquals(
    plugin.parse(`shse:${pubkey}:${extra}`),
    { pubkey: buf1, extra: buf2 },
    'parse pubkey+extra'
  )
  t.deepEquals(plugin.parse(`shse:notgreat`), null, 'parse invalid pubkey')
  t.deepEquals(
    plugin.parse(`shse:${pubkey}:notgreat`),
    null,
    'parse invalid extra'
  )
  t.end()
})
