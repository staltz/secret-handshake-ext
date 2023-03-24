// will probably remove this.
// I am now moving using secret-handshake via
// https://github.com/dominictarr/multiserver
// instead.

const net = require('net')
const sodium = require('chloride')
const toPull = require('stream-to-pull-stream')
const pull = require('pull-stream')
const Defer = require('pull-defer/duplex')
const shs = require('../')

const isBuffer = Buffer.isBuffer

function assertOpts(opts) {
  if (!(opts && 'object' === typeof opts))
    throw new Error('opts *must* be provided')
}

function assertKeys(opts) {
  if (
    !(
      opts.keys &&
      isBuffer(opts.keys.publicKey) &&
      isBuffer(opts.keys.secretKey)
    )
  ) {
    throw new Error('opts.keys = ed25519 key pair *must* be provided.')
  }
}

function assertAppKey(opts) {
  if (!isBuffer(opts.appKey)) throw new Error('appKey must be provided')
}

function assertAddr(addr) {
  if (!isBuffer(addr.key))
    throw new Error('opts.key *must* be an ed25519 public key')
  if (!Number.isInteger(+addr.port))
    throw new Error('opts.port *must* be provided')
  if (!('string' === typeof addr.host || null == addr.host))
    throw new Error('opts.host must be string or null')
}

module.exports = function createNode(opts) {
  const keys = isBuffer(opts.seed)
    ? sodium.crypto_sign_seed_keypair(opts.seed)
    : opts.keys

  assertOpts(opts)
  assertKeys({ keys })
  assertAppKey(opts)

  const create = shs.createClient(keys, opts.appKey, opts.timeout)

  return {
    publicKey: keys.publicKey,
    createServer(onConnect) {
      if (typeof opts.authenticate !== 'function') {
        throw new Error(
          'function opts.authenticate(pub, cb)' +
            '*must* be provided in order to receive connections'
        )
      }
      const createServerStream = shs.createServer(
        keys,
        opts.authenticate,
        opts.appKey,
        opts.timeout
      )
      let server
      return (server = net.createServer((stream) => {
        stream = toPull.duplex(stream)
        pull(
          stream,
          createServerStream((err, stream) => {
            if (err) return server.emit('unauthenticated', err)
            onConnect(stream)
          }),
          stream
        )
      }))
    },
    connect(addr, cb) {
      assertAddr(addr)
      const stream = toPull.duplex(net.connect(addr.port, addr.host))

      if (cb) {
        pull(stream, create(addr.key, cb), stream)
      } else {
        const defer = Defer()

        pull(
          stream,
          create(addr.key, (err, stream) => {
            if (err) {
              defer.resolve({
                source: pull.error(err),
                sink: (read) => read(err, () => {}),
              })
            } else {
              defer.resolve(stream)
            }
          }),
          stream
        )

        return defer
      }
    },
  }
}
