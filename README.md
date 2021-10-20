# libp2p-crypto
[![CI](https://github.com/helium/libp2p-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/helium/libp2p-crypto/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/helium/libp2p-crypto/branch/master/graph/badge.svg?token=h7C8KMXO8K)](https://codecov.io/gh/helium/libp2p-crypto)
[![Hex.pm](https://img.shields.io/hexpm/v/libp2p_crypto)](https://hex.pm/packages/libp2p_crypto)

This is a library of cryptography functions used by Helium's Erlang libp2p implementation.

The library knows how to create and use three different types of key
systems:

1. [ecc_compact](https://hex.pm/packages/ecc_compact),
2. [ed25519](https://hex.pm/packages/enacl), and
3. [secp256k1](https://www.secg.org/sec2-v2.pdf).

ecc_compact keys are used for addressing hardware-constrained nodes in the
system, while ed25519 and secp256k1 keys are used for user wallets since
they are often managed by systems under less constraints.


## Using the library

Add the library to your `rebar.config` deps section:

```erlang
{deps, [
        {libp2p_crypto, "1.0.1"},
        ...
       ]}.
```

## Creating a keypair

Creating an ecc_compact keypair

```erlang
KeyMap = #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ecc_compact).
```

An ed25519 key:

```erlang
KeyMap = #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ed25519).
```

And a secp256k1 key:

```erlang
KeyMap = #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(secp256k1).
```

## Saving/Loading keys

Storing keypairs on disk should be considered very carefully from a
security perspective since the resulting file will include both the
public and private key.

If the system supports hardware key storage, use it instead of storing
secrets on disk. That said, many systems don't support hardware key
storage so here is how to save keys:

```erlang
ok = libp2p_crypto:save_keys(KeyMap, "keys.dat").
```

and load them:

```erlang
{ok, KeyMap} = libp2p_crypto:load_keys("keys.dat").
```


## Encodings

If you need to pass a public key over the network you will have to
convert it to a binary form the other side can decode:

```erlang
PubBin = libp2p_crypto:pubkey_to_bin(PubKey).
```

And to have the other side to decode a given binary:

```erlang
PubKey = libp2p_crypto:bin_to_pubkey(PubBin).
```

To encode a public key as a string that is somewhat resilient to copy
paste or other errors encode it as a base58 check encoded string
using:

```erlang
B58String = libp2p_crypto:pubkey_to_b58(PubKey).
```

And to decode a base58 check encoded string:

```erlang
PubKey = libp2p_crypto:b58_to_pubkey(B58String).
```

A public key is also often used to _address_ a node in the network
using _p2p_ [multiaddr](https://hex.pm/packages/multiaddr) string
encoding. To encode a public key to a p2p address:

```erlang
P2PAddr = libp2p_crypto:pubkey_bin_to_p2p(libp2p_crypto:pubkey_to_bin(PubKey)).
```

And to decode a p2p address to a public key:

```erlang
PubKeyBin = libp2p_crypto:bin_to_pubkey(libp2p_crypto:p2p_to_pubkey_bin(P2PAddr)).
```



## Signing

To support hardware key storage the libp2p_crypto library encourages
the use of a signing function instead of passing private keys around.

Creating a signing function for a given private key:

```erlang
SigFun = libp2p_crypto:mk_sig_fun(PrivKey).
```

To use the resulting function to sign some data:


```erlang
Signature = SigFun(<<"hello world">>).
```

And to verify the signature:

```erlang
true = libp2p_crypto:verify(<<"hello world">>, Signature, PubKey).
```
