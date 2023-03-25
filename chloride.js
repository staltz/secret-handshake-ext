const sodium = require('sodium-universal')

function keypairFromBuf(seed) {
  const out = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_seed_keypair(out.publicKey, out.secretKey, seed)
  return out
}

function curvify_pk(ed_pk) {
  const curve_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk)
  } catch {
    return null
  }
  return curve_pk
}

function curvify_sk(ed_sk) {
  const curve_sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk)
  return curve_sk
}

function auth(input, key) {
  const output = Buffer.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

function shared(localSecretKey, remotePublicKey) {
  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(sharedSecret, localSecretKey, remotePublicKey)
  return sharedSecret
}

function hash(input) {
  const output = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(output, input)
  return output
}

function sign(msg, sk) {
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, msg, sk)
  return sig
}

function verify(sig, msg, pk) {
  return sodium.crypto_sign_verify_detached(sig, msg, pk)
}

function verify_auth(output, input, key) {
  return sodium.crypto_auth_verify(output, input, key) ? 0 : 1
}

function box(ptxt, nonce, key) {
  const ctxt = Buffer.alloc(ptxt.length + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(ctxt, ptxt, nonce, key)
  return ctxt
}

function unbox(ctxt, nonce, key) {
  const ptxt = Buffer.alloc(ctxt.length - sodium.crypto_secretbox_MACBYTES)
  const unboxed = sodium.crypto_secretbox_open_easy(ptxt, ctxt, nonce, key)
  if (unboxed) return ptxt
  else return null
}

module.exports = {
  keypairFromBuf,
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
