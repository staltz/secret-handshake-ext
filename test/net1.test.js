const tape = require('tape')
const net = require('net')
const pull = require('pull-stream')
const toPull = require('stream-to-pull-stream')
const cl = require('chloride')
const shs = require('../')

function hash(str) {
  return cl.crypto_hash_sha256(Buffer.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const app_key = hash('app_key')

tape('test with net', (t) => {
  const createServer = shs.createServer(
    bob,
    (pub, cb) => cb(null, true), //accept
    app_key,
    100
  )

  const createClient = shs.createClient(alice, app_key, 100)

  const PORT = 45034

  const server = net
    .createServer((stream) => {
      stream = toPull.duplex(stream)

      pull(
        stream,
        createServer((err, stream) => {
          console.log('server connected', err, stream)
          pull(stream, stream) //echo
        }),
        stream
      )
    })
    .listen(PORT, () => {
      const stream = toPull.duplex(net.connect(PORT))

      console.log('CLIENT connect')
      pull(
        stream,
        createClient(bob.publicKey, (err, stream) => {
          console.log('client connected', err, stream)
          pull(
            pull.values([Buffer.from('HELLO')]),
            stream,
            pull.collect((err, data) => {
              t.notOk(err)
              t.deepEqual(Buffer.concat(data), Buffer.from('HELLO'))
              server.close()
              t.end()
            })
          )
        }),
        stream
      )
    })
})

tape('test with net', (t) => {
  let n = 2
  t.plan(2)
  const createServer = shs.createServer(
    bob,
    (pub, cb) => cb(), // reject with no reason
    app_key,
    100
  )

  const createClient = shs.createClient(alice, app_key, 100)

  const PORT = 45035

  const server = net
    .createServer((stream) => {
      stream = toPull.duplex(stream)

      pull(
        stream,
        createServer((err, stream) => {
          t.ok(err)
          console.log('server connected', err, stream)
          next()
        }),
        stream
      )
    })
    .listen(PORT, () => {
      const stream = toPull.duplex(net.connect(PORT))

      console.log('CLIENT connect')
      pull(
        stream,
        createClient(bob.publicKey, (err, stream) => {
          console.log('client connected', err, stream)
          t.ok(err)
          next()
        }),
        stream
      )
    })

  function next() {
    if (--n) return
    server.close()
  }
})
