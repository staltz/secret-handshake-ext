// @ts-ignore
const pull = require('pull-stream')
const base58 = require('bs58')
const SecretHandshakeExt = require('./index')

/**
 * @typedef {import('./crypto').ChlorideKeypair} Keypair
 *
 * @typedef {import('./protocol').Authorize} Authorize
 *
 * @typedef {(
 *   publicKey: string,
 *   extra: string | null,
 *   cb: (...args: [Error] | [null, boolean]) => void
 * ) => void
 * } Base58Authorize
 *
 * @typedef {{ pubkey: Buffer, extra: Buffer | null }} Parsed
 */

/**
 * @param {{
 *   keys: Keypair | Buffer,
 *   appKey: string | Buffer,
 *   auth?: Base58Authorize,
 *   authorize?: Base58Authorize,
 *   timeout: number,
 * }} opts
 */
function SHSE(opts) {
  if (!opts.keys) throw new Error('SHSe multiserver plugin needs opts.keys')
  const keypair = SecretHandshakeExt.toKeypair(opts.keys)
  const appKey =
    typeof opts.appKey === 'string'
      ? Buffer.from(base58.decode(opts.appKey))
      : opts.appKey
  const hiLevelAuth = opts.auth ?? opts.authorize ?? (() => true)
  const auth = /** @type {Authorize} */ (pubkeyBuf, extraBuf, cb) => {
    const pubkey = base58.encode(pubkeyBuf)
    const extra = extraBuf ? base58.encode(extraBuf) : null
    hiLevelAuth(pubkey, extra, cb)
  }

  const timeout = opts.timeout

  const server = SecretHandshakeExt.createServer(keypair, auth, appKey, timeout)
  const client = SecretHandshakeExt.createClient(keypair, appKey, opts.timeout)

  return {
    name: 'shse',
    /**
     * @param {Parsed} parsed
     */
    create(parsed) {
      /**
       * @param {any} stream
       * @param {(...args: [Error] | [null, any]) => void} cb
       */
      return function shseTransform(stream, cb) {
        /**
         * @param {any} err
         * @param {any=} _stream
         */
        function _cb(err, _stream) {
          if (err) {
            // shse is designed so that we do not _know_ who is connecting if it
            // fails, so we probably can't add the connecting address. (unless
            // it was client unauthorized)
            err.address = 'shse:'
            return cb(err)
          }
          _stream.address = 'shse:' + base58.encode(_stream.remote)
          cb(null, _stream)
        }

        const boxStream = parsed?.pubkey
          ? client(parsed.pubkey, parsed.extra, _cb)
          : server(_cb)

        pull(stream.source, boxStream, stream.sink)
      }
    },

    /**
     * @param {string} str
     */
    parse(str) {
      const [prefixStr, pubkeyStr, extraStr] = str.split(':')
      if (prefixStr !== 'shse') return null
      const pubkey = Buffer.from(base58.decode(pubkeyStr))
      if (pubkey.length !== 32) return null
      const extra = extraStr ? Buffer.from(base58.decode(extraStr)) : null
      if (extra && extra.length !== 32) return null
      return { pubkey, extra }
    },

    stringify() {
      if (!keypair) return
      return 'shse:' + base58.encode(keypair.publicKey)
    },

    pubkey: base58.encode(keypair.publicKey),
  }
}

module.exports = SHSE
