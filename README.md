# libp2p-crypto
[![Build status](https://badge.buildkite.com/7cd9c739d07cfe9879901bfb1139c73825557209f96a9aeb3e.svg)](https://buildkite.com/helium/libp2p-crypto)
[![codecov](https://codecov.io/gh/helium/libp2p_crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/helium/libp2p_crypto)
[![Hex.pm](https://img.shields.io/hexpm/v/libp2p_crypto)](https://hex.pm/packages/libp2p_crypto)

This is a library of cryptography functions used by Helium's Erlang libp2p implementation.

The library knows how to create and use two different types of key
systems, [ecc_compact](https://hex.pm/packages/ecc_compact) and
[ed25519](https://hex.pm/packages/enacl).

ecc_compact keys are used for addressing nodes in the system since
there is hardware support for ECC operations, while ed25519 keys are
used for user wallets since there are common browsed implementations
for this kind of key.


## Using the library

Add the library to your `rebar.config` deps section:

```
{deps, [
        {libp2p_crypto, "1.0.1"},
        ...
       ]}.
```

## Creating a keypair

Creating an ecc_compact keypair

```
KeyMap = #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ecc_compact).
```

And an ed25519 key:

```
KeyMap = #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ed25519).
```


## Saving/Loading keys

Storing keypairs on disk should be considered very carefully from a
security perspective since the resulting file will include both the
public and private key.

If the system supports hardware key storage use it instead of storing
secrets on disk. That said, many systems don't support hardware key
storage so here is how to save keys:

```
ok = libp2p_crypto:save_keys(KeyMap, "keys.dat").
```

and load them:

```
{ok, KeyMap} = libp2p_crypto:load_keys("keys.dat").
```


## Encodings

If you need to pass a public key over the network you will have to
convert it to a binary form the other side can decode:

```
PubBin = libp2p_crypto:pubkey_to_bin(PubKey).
```

And to have the other side to decode a given binary:

```
PubKey = libp2p_crypto:bin_to_pubkey(PubBin).
```

To encode a public key as a string that is somewhat resilient to copy
paste or other errors encode it as a base58 check encoded string
using:

```
B58String = libp2p_crypto:pubkey_to_b58(PubKey).
```

And to decode a base58 check encoded string:

```
PubKey = libp2p_crypto:b58_to_pubkey(B58String).
```

A public key is also often used to _address_ a node in the network
using _p2p_ [multiaddr](https://hex.pm/packages/multiaddr) string
encoding. To encode a public key to a p2p address:

```
P2PAddr = libp2p_crypto:pubkey_bin_to_p2p(libp2p_crypto:pubkey_to_bin(PubKey)).
```

And to decode a p2p address to a public key:

```
PubKeyBin = libp2p_crypto:bin_to_pubkey(libp2p_crypto:p2p_to_pubkey_bin(P2PAddr)).
```



## Signing

To support hardware key storage the libp2p_crypto library encourages
the use of a signing function instead of passing private keys around.

Creating a signing function for a given private key:

```
SigFun = libp2p_crypto:mk_sig_fun(PrivKey).
```

To use the resulting function to sign some data:


```
Signature = SigFun(<<"hello world">>).
```

And to verify the signature:

```
true = libp2p_crypto:verify(<<"hello world">>, Signature, PubKey).
```
