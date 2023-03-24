const pull = require('pull-stream')
const boxes = require('pull-box-stream')
const Handshake = require('pull-handshake')
const chloride = require('chloride')
const errors = require('./errors')

function createRandom(numBytes) {
  const buf = Buffer.alloc(numBytes)
  chloride.randombytes(buf, numBytes)
  return buf
}

function isBuffer(buf, len) {
  return Buffer.isBuffer(buf) && buf.length === len
}

function createAbort(shake) {
  return function abort(err, reason) {
    if (err && err !== true) {
      shake.abort(new Error(reason, { cause: err.message ?? err }))
    } else {
      shake.abort(new Error(reason))
    }
  }
}

const zero32 = Buffer.alloc(32, 0)

module.exports = function protocol(crypto) {
  // client is Alice
  // create the client stream with the public key you expect to connect to.
  function createClientStream(alice, app_key, timeout) {
    return function getClientStream(bob_pub, extra_token, cb) {
      let state = crypto.initialize({
        app_key,
        random: createRandom(32),
        extra: extra_token ?? zero32,
        local: alice,
        remote: { publicKey: bob_pub },
      })

      const stream = Handshake({ timeout }, cb) // cb called only for errors
      const shake = stream.handshake
      stream.handshake = null
      const abort = createAbort(shake)

      // phase 1: client sends challenge
      shake.write(crypto.createChallenge(state))

      // phase 2: receiving and verifying server's challenge
      shake.read(crypto.challenge_length, (err, msg) => {
        if (err) return abort(err, errors.serverErrorOnChallenge)
        if (!(state = crypto.clientVerifyChallenge(state, msg))) {
          return abort(null, errors.serverInvalidChallenge)
        }

        // phase 3: client sends hello (including proof they know the server)
        shake.write(crypto.clientCreateAuth(state))

        // phase 4: receiving and verifying server's acceptance
        shake.read(crypto.server_auth_length, (err, boxed_sig) => {
          if (err) return abort(err, errors.serverHungUp)
          if (!(state = crypto.clientVerifyAccept(state, boxed_sig))) {
            return abort(null, errors.serverAcceptInvalid)
          }

          // Conclude handshake
          cb(null, shake.rest(), (state = crypto.clean(state)))
        })
      })

      return stream
    }
  }

  // server is Bob.
  function createServerStream(bob, authorize, app_key, timeout) {
    return function getServerStream(cb) {
      let state = crypto.initialize({
        app_key,
        random: createRandom(32),
        local: bob,
        // remote: unknown until server receives ClientAuth
      })

      const stream = Handshake({ timeout }, cb) // cb called only for errors
      const shake = stream.handshake
      stream.handshake = null
      const abort = createAbort(shake)

      // phase 1: receiving and verifying client's challenge
      shake.read(crypto.challenge_length, (err, challenge) => {
        if (err) return abort(err, errors.clientErrorOnChallenge)
        if (!(state = crypto.verifyChallenge(state, challenge))) {
          return shake.abort(new Error(errors.clientInvalidChallenge))
        }

        // phase 2: server sends challenge
        shake.write(crypto.createChallenge(state))

        // phase 3: receiving and verifying client's hello
        shake.read(crypto.client_auth_length, (err, hello) => {
          if (err) return abort(err, errors.clientErrorOnHello)
          if (!(state = crypto.serverVerifyAuth(state, hello))) {
            return abort(null, errors.clientInvalidHello)
          }

          // phase 4: server decides if they want client to connect with them
          authorize(state.remote.publicKey, state.extra, (err, auth) => {
            if (err) return abort(err, errors.serverErrorOnAuthorization)
            if (!auth) return abort(null, errors.clientUnauthorized)
            state.auth = auth
            shake.write(crypto.serverCreateAccept(state))

            // Conclude handshake
            cb(null, shake.rest(), (state = crypto.clean(state)))
          })
        })
      })

      return stream
    }
  }

  // wrap the above into an actual handshake + encrypted session

  function wrapInBoxStream(cb) {
    return function (err, stream, state) {
      if (err) return cb(err)

      const encryptNonce = state.remote.app_mac.slice(0, 24)
      const decryptNonce = state.local.app_mac.slice(0, 24)

      cb(null, {
        remote: state.remote.publicKey,
        // on the server, attach any metadata gathered
        // during `authorize` call
        auth: state.auth,
        crypto: {
          encryptKey: state.encryptKey,
          decryptKey: state.decryptKey,
          encryptNonce: encryptNonce,
          decryptNonce: decryptNonce,
        },
        source: pull(
          stream.source,
          boxes.createUnboxStream(state.decryptKey, decryptNonce)
        ),
        sink: pull(
          boxes.createBoxStream(state.encryptKey, encryptNonce),
          stream.sink
        ),
      })
    }
  }

  function createClient(alice, app_key, timeout) {
    const getBoxStream = createClientStream(alice, app_key, timeout)

    return function createClientBoxStream(bob_pub, extra_token, cb) {
      if (!isBuffer(bob_pub, 32)) {
        throw new Error('createClient *must* be passed a public key')
      }
      if (extra_token && !isBuffer(extra_token, 32)) {
        throw new Error('createClient extra token *must* have 32 bytes')
      }
      return getBoxStream(bob_pub, extra_token, wrapInBoxStream(cb))
    }
  }

  function createServer(bob, authorize, app_key, timeout) {
    const getBoxStream = createServerStream(bob, authorize, app_key, timeout)

    return function createServerBoxStream(cb) {
      return getBoxStream(wrapInBoxStream(cb))
    }
  }

  return {
    createClient,
    createServer,
    client: createClient,
    server: createServer,
    toKeys: crypto.toKeys,
  }
}
