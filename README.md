# secret-handshake-ext

> This library is a small tweak to the original [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake)
protocol, with an extra 32 bytes payload that allows the server to recognize the
client based on a pre-agreed token.

The API differs from `secret-handshake` only in (server's )`authorize()` and
(client's) `createClientBoxStream()`, now receiving a 32-byte "extra" buffer.

```diff
-const SHS = require('secret-handshake')
+const SHS = require('secret-handshake-ext')
 const cl = require('chloride')
 const pull = require('pull-stream')

 const appKey = /* 32 random bytes */
 const alice = cl.crypto_sign_keypair()
 const bob = cl.crypto_sign_keypair()
+const extra = /* pre-agreed 32 bytes */

-function authorize(pubkey, cb) {
+function authorize(pubkey, extra, cb) {
   // Server checks whether pubkey+extra is authorized to connect
   cb(null, check(pubkey, extra))
 }

 // Initialize
 const createServerBoxStream = SHS.server(alice, authorize, appKey)
 const createClientBoxStream = SHS.client(bob, appkey)

 const aliceStream = createServerBoxStream((err, stream) => {
   ...
 })

-const bobStream = createClientBoxStream(alice.publicKey, (err, stream) => {
+const bobStream = createClientBoxStream(alice.publicKey, extra, (err, stream) => {
   ...
 })

 // Simulate a streaming network connection by connecting streams together
 pull(aliceStream, bobStream, aliceStream)
```

This module also contains a multiserver plugin at
`secret-handshake-ext/lib/multiserver-plugin` and a secret-stack plugin at
`secret-handshake-ext/lib/secret-stack-plugin` (which wraps the multiserver
plugin).

## License

MIT
