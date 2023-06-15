const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const b4a = require('b4a')
const cl = require('chloride')
const pull = require('pull-stream')
const netshs = require('./net')

function hash(str) {
  return cl.crypto_hash_sha256(b4a.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const app_key = crypto.randomBytes(32)

const bobNode = netshs({
  keypair: bob,
  appKey: app_key,
  authenticate(pub, extra, cb) {
    cb(null, true) // accept anyone
  },
  timeout: 200,
})

const aliceNode = netshs({
  keypair: alice,
  appKey: app_key,
  timeout: 200,
  // alice doesn't need authenticate
  // because she is the client.
})
const PORT = 45034

test('test net.js, correct, callback', (t, done) => {
  const tcpServer = bobNode
    .createServer((stream) => {
      assert.equal(
        b4a.isBuffer(stream.remote) &&
          b4a.isBuffer(alice.publicKey) &&
          stream.remote.equals(alice.publicKey),
        true,
        "client's ID is Alice's ID"
      )

      pull(stream, stream) // echo
    })
    .listen(() => {
      const port = tcpServer.address().port
      aliceNode.connect(
        { host: 'localhost', port, key: bob.publicKey },
        (err, stream) => {
          assert.ifError(err)
          assert.equal(
            b4a.isBuffer(stream.remote) &&
              b4a.isBuffer(bob.publicKey) &&
              stream.remote.equals(bob.publicKey),
            true,
            "server's ID is Bob's ID"
          )

          pull(
            pull.values([b4a.from('HELLO')]),
            stream,
            pull.collect((err, data) => {
              assert.ifError(err)
              assert.deepEqual(b4a.concat(data), b4a.from('HELLO'), 'echo')
              tcpServer.close(done)
            })
          )
        }
      )
    })
})

test('test net.js, correct, stream directly', (t, done) => {
  const tcpServer = bobNode
    .createServer((stream) => {
      assert.equal(
        b4a.isBuffer(stream.remote) &&
          b4a.isBuffer(alice.publicKey) &&
          stream.remote.equals(alice.publicKey),
        true,
        "client's ID is Alice's ID"
      )

      pull(stream, stream) // echo
    })
    .listen(() => {
      const port = tcpServer.address().port
      pull(
        pull.values([b4a.from('HELLO')]),
        aliceNode.connect({ port, key: bob.publicKey }),
        pull.collect((err, data) => {
          assert.ifError(err)
          assert.deepEqual(b4a.concat(data), b4a.from('HELLO'), 'echo')
          tcpServer.close(done)
        })
      )
    })
})

const bobNode2 = netshs({
  keypair: bob,
  appKey: app_key,
  authenticate(pub, extra, cb) {
    cb() // reject with no reason
  },
})

test('test net, error, callback', (t, done) => {
  const tcpServer = bobNode2
    .createServer((stream) => {
      done(new Error('this should never be called'))
    })
    .listen(() => {
      const port = tcpServer.address().port
      // t.pass('client connect')
      aliceNode.connect({ port, key: bob.publicKey }, (err) => {
        assert.ok(err, 'client got connection error')
        assert.match(
          err.message,
          /server does not wish to talk to us/,
          'client got rejection'
        )
        tcpServer.close(done)
      })
    })
})

test('test net, error, stream', (t, done) => {
  const tcpServer = bobNode2
    .createServer((stream) => {
      done(new Error('this should never be called'))
    })
    .listen(() => {
      const port = tcpServer.address().port
      pull(
        aliceNode.connect({ port, key: bob.publicKey }),
        pull.collect((err, ary) => {
          assert.ok(err, 'client got connection error')
          assert.match(
            err.message,
            /server does not wish to talk to us/,
            'client got rejection'
          )
          tcpServer.close(done)
        })
      )
    })
})

test('test net, create seed cap', (t, done) => {
  const seed = crypto.randomBytes(32)
  const keypair = cl.crypto_sign_seed_keypair(seed)

  const seedNode = netshs({
    seed: seed,
    appKey: app_key,
    // alice doesn't need authenticate
    // because she is the client.
  })

  const server = bobNode
    .createServer((stream) => {
      assert.equal(
        b4a.isBuffer(stream.remote) &&
          b4a.isBuffer(keypair.publicKey) &&
          stream.remote.equals(keypair.publicKey),
        true,
        "client's ID is correct"
      )

      stream.source(true, () => {})
      server.close(done)
    })
    .listen(() => {
      const port = server.address().port
      seedNode.connect({ port, key: bob.publicKey })
    })
})
