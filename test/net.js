// This file is a precursor to multiserver with shs plugin

const net = require('node:net')
const b4a = require('b4a')
const sodium = require('chloride')
const pull = require('pull-stream')
const Defer = require('pull-defer/duplex')
const toPull = require('stream-to-pull-stream')
const shs = require('../')

function assertAppKey(opts) {
  if (!b4a.isBuffer(opts.appKey)) throw new Error('appKey must be provided')
}

function assertKeypair(keypair) {
  if (
    !(
      keypair &&
      b4a.isBuffer(keypair.publicKey) &&
      b4a.isBuffer(keypair.secretKey)
    )
  ) {
    throw new Error('opts.keypair = ed25519 key pair *must* be provided.')
  }
}

function assertAddr(addr) {
  if (!b4a.isBuffer(addr.key))
    throw new Error('opts.key *must* be an ed25519 public key')
  if (!Number.isInteger(+addr.port))
    throw new Error('opts.port *must* be provided')
  if (!('string' === typeof addr.host || null == addr.host))
    throw new Error('opts.host must be string or null')
}

module.exports = function createNode(opts = {}) {
  const keypair = b4a.isBuffer(opts.seed)
    ? sodium.crypto_sign_seed_keypair(opts.seed)
    : opts.keypair

  assertAppKey(opts)
  assertKeypair(keypair)

  const createClientBoxStream = shs.createClient(
    keypair,
    opts.appKey,
    opts.timeout
  )

  return {
    publicKey: keypair.publicKey,
    createServer(onConnect) {
      if (typeof opts.authenticate !== 'function') {
        throw new Error(
          'function opts.authenticate(pub, cb)' +
            '*must* be provided in order to receive connections'
        )
      }
      const createServerBoxStream = shs.createServer(
        keypair,
        opts.authenticate,
        opts.appKey,
        opts.timeout
      )
      let tcpServer
      return (tcpServer = net.createServer((serverDuplex) => {
        serverDuplex = toPull.duplex(serverDuplex)
        pull(
          serverDuplex,
          createServerBoxStream((err, stream) => {
            if (err) return tcpServer.emit('unauthenticated', err)
            onConnect(stream)
          }),
          serverDuplex
        )
      }))
    },
    connect(addr, cb) {
      assertAddr(addr)
      const clientDuplex = toPull.duplex(net.connect(addr.port, addr.host))

      if (cb) {
        pull(
          clientDuplex,
          createClientBoxStream(addr.key, addr.extra, cb),
          clientDuplex
        )
      } else {
        const defer = Defer()

        pull(
          clientDuplex,
          createClientBoxStream(addr.key, addr.extra, (err, stream) => {
            if (err) {
              defer.resolve({
                source: pull.error(err),
                sink: (read) => read(err, () => {}),
              })
            } else {
              defer.resolve(stream)
            }
          }),
          clientDuplex
        )

        return defer
      }
    },
  }
}
