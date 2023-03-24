const sodium = require('chloride')

const keypairFromBuf = sodium.crypto_sign_seed_keypair
const shared = sodium.crypto_scalarmult
const hash = sodium.crypto_hash_sha256
const sign = sodium.crypto_sign_detached
const verify = sodium.crypto_sign_verify_detached
const auth = sodium.crypto_auth
const verify_auth = sodium.crypto_auth_verify
const curvify_pk = sodium.crypto_sign_ed25519_pk_to_curve25519
const curvify_sk = sodium.crypto_sign_ed25519_sk_to_curve25519
const box = sodium.crypto_secretbox_easy
const unbox = sodium.crypto_secretbox_open_easy

const concat = Buffer.concat
const isBuffer = Buffer.isBuffer

const nonce = Buffer.alloc(24, 0)

const challenge_length = 64
const client_auth_length = 16 + 32 + 64
const server_auth_length = 16 + 64
const mac_length = 16

// both client and server

function assert_length(buf, name, length) {
  if (buf.length !== length) {
    throw new Error(
      `expected ${name} to have length ${length}, but was: ${buf.length}`
    )
  }
}

function initialize(state) {
  const kx = keypairFromBuf(state.random)
  const kx_pk = curvify_pk(kx.publicKey)
  const kx_sk = curvify_sk(kx.secretKey)

  state.local = {
    kx_pk: kx_pk,
    kx_sk: kx_sk,
    publicKey: state.local.publicKey,
    secretKey: state.local.secretKey,
    app_mac: auth(kx_pk, state.app_key),
  }

  state.remote ??= {}

  return state
}

function createChallenge(state) {
  return concat([state.local.app_mac, state.local.kx_pk])
}

function verifyChallenge(state, challenge) {
  assert_length(challenge, 'challenge', challenge_length)

  const mac = challenge.slice(0, 32)
  const remote_pk = challenge.slice(32, challenge_length)

  if (0 !== verify_auth(mac, remote_pk, state.app_key)) return null

  state.remote.kx_pk = remote_pk
  state.remote.app_mac = mac
  state.secret = shared(state.local.kx_sk, state.remote.kx_pk)
  state.shash = hash(state.secret)

  return state
}

function clean(state) {
  // clean away all the secrets for forward security.
  // use a different secret hash(secret3) in the rest of the session,
  // and so that a sloppy application cannot compromise the handshake.

  state.shash.fill(0)
  state.secret.fill(0)
  state.a_bob.fill(0)
  state.b_alice.fill(0)

  state.secret = hash(state.secret3)
  state.encryptKey = hash(concat([state.secret, state.remote.publicKey]))
  state.decryptKey = hash(concat([state.secret, state.local.publicKey]))

  state.secret2.fill(0)
  state.secret3.fill(0)
  state.local.kx_sk.fill(0)

  state.shash = null
  state.secret2 = null
  state.secret3 = null
  state.a_bob = null
  state.b_alice = null
  state.local.kx_sk = null
  return state
}

// client side only (Alice)

function clientVerifyChallenge(state, challenge) {
  assert_length(challenge, 'challenge', challenge_length)
  state = verifyChallenge(state, challenge)
  if (!state) return null

  // now we have agreed on the secret.
  // this can be an encryption secret,
  // or a hmac secret.
  const curve = curvify_pk(state.remote.publicKey)
  if (!curve) return null
  const a_bob = shared(state.local.kx_sk, curve)
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  const signed = concat([state.app_key, state.remote.publicKey, state.shash])
  const sig = sign(signed, state.local.secretKey)

  state.local.hello = Buffer.concat([sig, state.local.publicKey])
  return state
}

function clientCreateAuth(state) {
  return box(state.local.hello, nonce, state.secret2)
}

function clientVerifyAccept(state, boxed_okay) {
  assert_length(boxed_okay, 'server_auth', server_auth_length)

  const b_alice = shared(curvify_sk(state.local.secretKey), state.remote.kx_pk)
  state.b_alice = b_alice
  state.secret3 = hash(
    concat([state.app_key, state.secret, state.a_bob, state.b_alice])
  )

  const sig = unbox(boxed_okay, nonce, state.secret3)
  if (!sig) return null
  const signed = concat([state.app_key, state.local.hello, state.shash])
  if (!verify(sig, signed, state.remote.publicKey)) return null
  return state
}

// server side only (Bob)

function serverVerifyAuth(state, data) {
  assert_length(data, 'client_auth', client_auth_length)

  const a_bob = shared(curvify_sk(state.local.secretKey), state.remote.kx_pk)
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  state.remote.hello = unbox(data, nonce, state.secret2)
  if (!state.remote.hello) return null

  const sig = state.remote.hello.slice(0, 64)
  const publicKey = state.remote.hello.slice(64, 96)

  const signed = concat([state.app_key, state.local.publicKey, state.shash])
  if (!verify(sig, signed, publicKey)) return null

  state.remote.publicKey = publicKey
  // shared key between my local ephemeral key + remote public
  const b_alice = shared(state.local.kx_sk, curvify_pk(state.remote.publicKey))
  state.b_alice = b_alice
  state.secret3 = hash(
    concat([state.app_key, state.secret, state.a_bob, state.b_alice])
  )

  return state
}

function serverCreateAccept(state) {
  const signed = concat([state.app_key, state.remote.hello, state.shash])
  const okay = sign(signed, state.local.secretKey)
  return box(okay, nonce, state.secret3)
}

function toKeys(keys) {
  if (isBuffer(keys, 32)) return keypairFromBuf(keys)
  return keys
}

module.exports = {
  challenge_length,
  client_auth_length,
  server_auth_length,
  mac_length,

  clean,
  initialize,
  createChallenge,
  verifyChallenge,
  clientVerifyChallenge,
  clientCreateAuth,
  clientVerifyAccept,
  serverVerifyAuth,
  serverCreateAccept,
  toKeys,
}
