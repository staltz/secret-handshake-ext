// This file is a precursor to multiserver with shs plugin

const net = require('net')
const sodium = require('chloride')
const toPull = require('stream-to-pull-stream')
const pull = require('pull-stream')
const Defer = require('pull-defer/duplex')
const shs = require('../')

const isBuffer = Buffer.isBuffer

function assertAppKey(opts) {
  if (!isBuffer(opts.appKey)) throw new Error('appKey must be provided')
}

function assertKeys(keys) {
  if (!(keys && isBuffer(keys.publicKey) && isBuffer(keys.secretKey))) {
    throw new Error('opts.keys = ed25519 key pair *must* be provided.')
  }
}

function assertAddr(addr) {
  if (!isBuffer(addr.key))
    throw new Error('opts.key *must* be an ed25519 public key')
  if (!Number.isInteger(+addr.port))
    throw new Error('opts.port *must* be provided')
  if (!('string' === typeof addr.host || null == addr.host))
    throw new Error('opts.host must be string or null')
}

module.exports = function createNode(opts = {}) {
  const keys = isBuffer(opts.seed)
    ? sodium.crypto_sign_seed_keypair(opts.seed)
    : opts.keys

  assertAppKey(opts)
  assertKeys(keys)

  const createClientBoxStream = shs.createClient(
    keys,
    opts.appKey,
    opts.timeout
  )

  return {
    publicKey: keys.publicKey,
    createServer(onConnect) {
      if (typeof opts.authenticate !== 'function') {
        throw new Error(
          'function opts.authenticate(pub, cb)' +
            '*must* be provided in order to receive connections'
        )
      }
      const createServerBoxStream = shs.createServer(
        keys,
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
        pull(clientDuplex, createClientBoxStream(addr.key, cb), clientDuplex)
      } else {
        const defer = Defer()

        pull(
          clientDuplex,
          createClientBoxStream(addr.key, (err, stream) => {
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
