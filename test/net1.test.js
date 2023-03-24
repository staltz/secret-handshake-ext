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

tape('test with TCP and always-accepting server', (t) => {
  function accept(pub, cb) {
    cb(null, true)
  }

  const createServerBoxStream = shs.createServer(bob, accept, app_key, 100)
  const createClientBoxStream = shs.createClient(alice, app_key, 100)

  const tcpServer = net
    .createServer((stream) => {
      const serverDuplex = toPull.duplex(stream)

      pull(
        serverDuplex,
        createServerBoxStream((err, unboxedStream) => {
          t.pass('server connected')
          pull(unboxedStream, unboxedStream) // echo
        }),
        serverDuplex
      )
    })
    .listen(() => {
      const port = tcpServer.address().port
      const clientDuplex = toPull.duplex(net.connect(port))

      t.pass('client connecting')
      pull(
        clientDuplex,
        createClientBoxStream(bob.publicKey, (err, unboxedStream) => {
          t.pass('client connected')
          pull(
            pull.values([Buffer.from('HELLO')]),
            unboxedStream,
            pull.collect((err, data) => {
              t.error(err, 'no error')
              t.deepEqual(Buffer.concat(data), Buffer.from('HELLO'))
              tcpServer.close()
              t.end()
            })
          )
        }),
        clientDuplex
      )
    })
})

tape('test with TCP and always-rejecting server', (t) => {
  let n = 2
  t.plan(4)

  function reject(pub, cb) {
    cb(null, false)
  }

  const createServerBoxStream = shs.createServer(bob, reject, app_key, 100)
  const createClientBoxStream = shs.createClient(alice, app_key, 100)

  const tcpServer = net
    .createServer((stream) => {
      const serverDuplex = toPull.duplex(stream)

      pull(
        serverDuplex,
        createServerBoxStream((err) => {
          t.pass('server got connection request')
          t.match(err.message, /did not authorize/, 'server rejects')
          next()
        }),
        serverDuplex
      )
    })
    .listen(() => {
      const port = tcpServer.address().port
      const clientDuplex = toPull.duplex(net.connect(port))

      t.pass('client connecting')
      pull(
        clientDuplex,
        createClientBoxStream(bob.publicKey, (err) => {
          t.match(err.message, /does not wish to talk/, 'client got rejection')
          next()
        }),
        clientDuplex
      )
    })

  function next() {
    if (--n) return
    tcpServer.close()
  }
})
