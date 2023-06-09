// @ts-ignore
const sodium = require('sodium-universal')

/**
 * @param {Buffer} seed
 * @returns {{ publicKey: Buffer, secretKey: Buffer}}
 */
function keypairFromBuf(seed) {
  const out = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_seed_keypair(out.publicKey, out.secretKey, seed)
  return out
}

/**
 * @param {number} numBytes
 * @returns {Buffer}
 */
function createRandom(numBytes) {
  const buf = Buffer.alloc(numBytes)
  sodium.randombytes_buf(buf)
  return buf
}

/**
 * @param {Buffer} ed_pk
 * @returns {Buffer | null}
 */
function curvify_pk(ed_pk) {
  const curve_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk)
  } catch {
    return null
  }
  return curve_pk
}

/**
 * @param {Buffer} ed_sk
 * @returns {Buffer}
 */
function curvify_sk(ed_sk) {
  const curve_sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk)
  return curve_sk
}

/**
 * @param {Buffer} input
 * @param {Buffer} key
 * @returns {Buffer}
 */
function auth(input, key) {
  const output = Buffer.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * @param {Buffer} localSecretKey
 * @param {Buffer} remotePublicKey
 * @returns {Buffer}
 */
function shared(localSecretKey, remotePublicKey) {
  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(sharedSecret, localSecretKey, remotePublicKey)
  return sharedSecret
}

/**
 * @param {Buffer} input
 * @returns {Buffer}
 */
function hash(input) {
  const output = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(output, input)
  return output
}

/**
 * @param {Buffer} msg
 * @param {Buffer} sk
 * @returns {Buffer}
 */
function sign(msg, sk) {
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, msg, sk)
  return sig
}

/**
 * @param {Buffer} sig
 * @param {Buffer} msg
 * @param {Buffer} pk
 * @returns {boolean}
 */
function verify(sig, msg, pk) {
  return sodium.crypto_sign_verify_detached(sig, msg, pk)
}

/**
 * @param {Buffer} output
 * @param {Buffer} input
 * @param {Buffer} key
 * @returns {0 | 1}
 */
function verify_auth(output, input, key) {
  return sodium.crypto_auth_verify(output, input, key) ? 0 : 1
}

/**
 * @param {Buffer} ptxt
 * @param {Buffer} nonce
 * @param {Buffer} key
 * @returns {Buffer}
 */
function box(ptxt, nonce, key) {
  const ctxt = Buffer.alloc(ptxt.length + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(ctxt, ptxt, nonce, key)
  return ctxt
}

/**
 * @param {Buffer} ctxt
 * @param {Buffer} nonce
 * @param {Buffer} key
 * @returns {Buffer | null}
 */
function unbox(ctxt, nonce, key) {
  const ptxt = Buffer.alloc(ctxt.length - sodium.crypto_secretbox_MACBYTES)
  const unboxed = sodium.crypto_secretbox_open_easy(ptxt, ctxt, nonce, key)
  if (unboxed) return ptxt
  else return null
}

module.exports = {
  keypairFromBuf,
  createRandom,
  curvify_pk,
  curvify_sk,
  auth,
  shared,
  hash,
  sign,
  verify,
  verify_auth,
  box,
  unbox,
}
