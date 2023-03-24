const tape = require('tape')
const crypto = require('crypto')
const pull = require('pull-stream')
const cl = require('chloride')
const netshs = require('./net')

function hash(str) {
  return cl.crypto_hash_sha256(Buffer.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const app_key = crypto.randomBytes(32)

const bobN = netshs({
  keys: bob,
  appKey: app_key,
  authenticate(pub, cb) {
    cb(null, true) // accept
  },
  timeout: 200,
})

const aliceN = netshs({
  keys: alice,
  appKey: app_key,
  timeout: 200,
  // alice doesn't need authenticate
  // because she is the client.
})
const PORT = 45034

tape('test net.js, correct, callback', (t) => {
  const server = bobN
    .createServer((stream) => {
      t.deepEqual(stream.remote, alice.publicKey)
      pull(stream, pull.through(console.log), stream) //echo
    })
    .listen(PORT, () => {
      aliceN.connect(
        { host: 'localhost', port: PORT, key: bob.publicKey },
        (err, stream) => {
          if (err) t.fail(err.message ?? err)
          t.deepEqual(stream.remote, bob.publicKey)
          pull(
            pull.values([Buffer.from('HELLO')]),
            stream,
            pull.collect((err, data) => {
              if (err) t.fail(err.message ?? err)
              t.notOk(err)
              t.deepEqual(Buffer.concat(data), Buffer.from('HELLO'))
              server.close()
              t.end()
            })
          )
        }
      )
    })
})

tape('test net.js, correct, stream directly', (t) => {
  const server = bobN
    .createServer((stream) => {
      t.deepEqual(stream.remote, alice.publicKey)
      pull(stream, pull.through(console.log), stream) //echo
    })
    .listen(PORT, () => {
      pull(
        pull.values([Buffer.from('HELLO')]),
        aliceN.connect({ port: PORT, key: bob.publicKey }),
        pull.collect((err, data) => {
          if (err) t.fail(err.message ?? err)
          t.notOk(err)
          t.deepEqual(Buffer.concat(data), Buffer.from('HELLO'))
          server.close()
          t.end()
        })
      )
    })
})

const bobN2 = netshs({
  keys: bob,
  appKey: app_key,
  authenticate(pub, cb) {
    cb() // reject with no reason
  },
})

tape('test net, error, callback', (t) => {
  const server = bobN2
    .createServer((stream) => {
      t.fail('this should never be called')
    })
    .listen(PORT, () => {
      console.log('CLIENT connect')
      aliceN.connect({ port: PORT, key: bob.publicKey }, (err, stream) => {
        console.log('client connected', err, stream)
        t.ok(err)
        t.end()
        server.close()
      })
    })
})

tape('test net, error, stream', (t) => {
  const server = bobN2
    .createServer((stream) => {
      t.fail('this should never be called')
    })
    .listen(PORT, () => {
      pull(
        aliceN.connect({
          port: PORT,
          key: bob.publicKey,
        }),
        pull.collect((err, ary) => {
          t.ok(err)
          t.end()
          server.close()
        })
      )
    })
})

tape('test net, create seed cap', (t) => {
  const seed = crypto.randomBytes(32)
  const keys = cl.crypto_sign_seed_keypair(seed)

  const seedN = netshs({
    seed: seed,
    appKey: app_key,
    // alice doesn't need authenticate
    // because she is the client.
  })

  const server = bobN
    .createServer((stream) => {
      t.deepEqual(stream.remote, keys.publicKey)
      stream.source(true, () => {})
      server.close()
      t.end()
    })
    .listen(PORT, () => {
      seedN.connect({ port: PORT, key: bob.publicKey })
    })
})
