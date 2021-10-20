-module(libp2p_crypto).

-include_lib("public_key/include/public_key.hrl").

%% The binary key representation is a leading byte followed by the key material
%% (either public or private).
%%
%% In order to support different networks (e.g. mainnet and testnet)
%% the leading byte is split into two four bit parts.
%% The first nibble is the network the key is on (NETTTYPE), and the second
%% the type of keythat follows in the binary (KEYTYPE).
-define(KEYTYPE_ECC_COMPACT, 0).
-define(KEYTYPE_ED25519, 1).
-define(KEYTYPE_MULTISIG, 2).
-define(KEYTYPE_SECP256K1, 3).
%% Do not ever assign to the reserved slot, it must be used as an extension
%% mechanism for future expansion, if needed.
-define(KEYTYPE_RESERVED, 15).

-define(NETTYPE_MAIN, 0).
-define(NETTYPE_TEST, 1).

-define(MULTISIG_SIG_LEN_BYTES,  8). %% signatures can be up to 256 bytes
-define(MULTISIG_KEY_INDEX_BITS, 8). %% up to 256 keys

-define(PRIMITIVE_KEY_TYPES, [
                              ecc_compact,
                              ed25519,
                              secp256k1
                             ]).

%% used for testing and known/unknown checking
-define(MULTI_HASH_TYPES_ALL, [
    identity,
    sha1,
    sha2_256,
    sha2_512,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    keccak224,
    keccak256,
    keccak384,
    keccak512,
    blake2b256,
    blake2b512,
    blake2s128,
    blake2s256
]).
-define(MULTI_HASH_TYPE_DEFAULT,
    sha2_256
).
-define(MULTI_HASH_TYPES_SUPPORTED, [
    sha2_256,
    sha3_256,
    blake2b256
]).
-define(MULTI_HASH_TYPES_DEPRECATED, []). %% used ONLY in verify

-type key_type() :: ecc_compact | ed25519 | secp256k1.
-type network() :: mainnet | testnet.
-opaque privkey() ::
    {ecc_compact, ecc_compact:private_key()}
    | {ed25519, enacl_privkey()}
    | {secp256k1, ecc_compact:private_key()}.

-opaque pubkey_multi() ::
    {multisig, pos_integer(), pos_integer(), binary()}.

-opaque pubkey_single() ::
    {ecc_compact, ecc_compact:public_key_p256()}
    | {ed25519, enacl_pubkey()}
    | {secp256k1, ecc_compact:public_key_k256()}.

-opaque pubkey() ::
    pubkey_single() | pubkey_multi().

-type pubkey_bin() :: <<_:8, _:_*8>>.
-type sig_fun() :: fun((binary()) -> binary()).
-type ecdh_fun() :: fun((pubkey()) -> binary()).
-type key_map() :: #{secret => privkey(), public => pubkey(), network => network()}.
-type enacl_privkey() :: <<_:256>>.
-type enacl_pubkey() :: <<_:256>>.

-export_type([
    privkey/0,
    pubkey/0,
    pubkey_bin/0,
    pubkey_multi/0,
    pubkey_single/0,
    sig_fun/0,
    ecdh_fun/0
]).

-export([
    get_network/1,
    set_network/1,
    generate_keys/1,
    generate_keys/2,
    mk_sig_fun/1,
    mk_ecdh_fun/1,
    load_keys/1,
    save_keys/2,
    pubkey_to_bin/1,
    pubkey_to_bin/2,
    bin_to_pubkey/1,
    bin_to_pubkey/2,
    bin_to_b58/1,
    bin_to_b58/2,
    b58_to_bin/1,
    b58_to_version_bin/1,
    pubkey_to_b58/1,
    pubkey_to_b58/2,
    b58_to_pubkey/1,
    b58_to_pubkey/2,
    pubkey_bin_to_p2p/1,
    p2p_to_pubkey_bin/1,
    verify/3,
    keys_to_bin/1,
    keys_from_bin/1,
    multisig_member_keys_sort/1,
    multisig_member_keys_sort/2,
    multisig_member_key_index/2,
    multisig_member_key_index/3,
    make_multisig_pubkey/4,
    make_multisig_pubkey/5,
    make_multisig_signature/5,
    pubkey_is_multisig/1
]).

-define(network, libp2p_crypto_network).

%% @doc Get the currrent network used for public and private keys.
%% If not set return the given default
-spec get_network(Default :: network()) -> network().
get_network(Default) ->
    persistent_term:get(?network, Default).

%% @doc Sets the network used for public and private keys.
-spec set_network(network()) -> ok.
set_network(Network) ->
    persistent_term:put(?network, Network).

%% @doc Generate keys suitable for a swarm.  The returned private and
%% public key has the attribute that the public key is a compressable
%% public key.
%%
%% The keys are generated on the currently active network.
-spec generate_keys(key_type()) -> key_map().
generate_keys(KeyType) ->
    generate_keys(get_network(mainnet), KeyType).

%% @doc Generate keys suitable for a swarm on a given network.
%% The returned private and public key has the attribute that
%% the public key is a compressable public key if ecc_compact is used.
-spec generate_keys(network(), key_type()) -> key_map().
generate_keys(Network, ecc_compact) ->
    {ok, PrivKey, CompactKey} = ecc_compact:generate_key(),
    PubKey = ecc_compact:recover_compact_key(CompactKey),
    #{
        secret => {ecc_compact, PrivKey},
        public => {ecc_compact, PubKey},
        network => Network
    };
generate_keys(Network, ed25519) ->
    #{public := PubKey, secret := PrivKey} = enacl:crypto_sign_ed25519_keypair(),
    #{
        secret => {ed25519, PrivKey},
        public => {ed25519, PubKey},
        network => Network
    };
generate_keys(Network, secp256k1) ->
    Key = public_key:generate_key({namedCurve,?secp256k1}),
    #'ECPrivateKey'{parameters=Params, publicKey=PubKeyPoint} = Key,
    PubKey = {#'ECPoint'{point = PubKeyPoint}, Params},
    #{
        secret => {secp256k1, Key},
        public => {secp256k1, PubKey},
        network => Network
    }.

%% @doc Load the private key from a pem encoded given filename.
%% Returns the private and extracted public key stored in the file or
%% an error if any occorred.
-spec load_keys(string()) -> {ok, key_map()} | {error, term()}.
load_keys(FileName) ->
    case file:read_file(FileName) of
        {ok, Bin} -> {ok, keys_from_bin(Bin)};
        {error, Error} -> {error, Error}
    end.

%% @doc Construct a signing function from a given private key. Using a
%% signature function instead of passing a private key around allows
%% different signing implementations, such as one built on a hardware
%% based security module.
-spec mk_sig_fun(privkey()) -> sig_fun().
mk_sig_fun({ecc_compact, PrivKey}) ->
    fun(Bin) -> public_key:sign(Bin, sha256, PrivKey) end;
mk_sig_fun({ed25519, PrivKey}) ->
    fun(Bin) -> enacl:sign_detached(Bin, PrivKey) end;
mk_sig_fun({secp256k1, PrivKey}) ->
    fun(Bin) -> public_key:sign(Bin, sha256, PrivKey) end.

%% @doc Constructs an ECDH exchange function from a given private key.
%%
%% Note that a Key Derivation Function should be applied to these keys
%% before use
-spec mk_ecdh_fun(privkey()) -> ecdh_fun().
mk_ecdh_fun({ecc_compact, PrivKey}) ->
    fun({ecc_compact, {PubKey, {namedCurve, ?secp256r1}}}) ->
        public_key:compute_key(PubKey, PrivKey)
    end;
mk_ecdh_fun({ed25519, PrivKey}) ->
    %% Do an X25519 ECDH exchange after converting the ED25519 keys to Curve25519 keys
    fun({ed25519, PubKey}) ->
        enacl:box_beforenm(
            enacl:crypto_sign_ed25519_public_to_curve25519(PubKey),
            enacl:crypto_sign_ed25519_secret_to_curve25519(PrivKey)
        )
    end;
mk_ecdh_fun({secp256k1, PrivKey}) ->
    fun({secp256k1, {PubKey, {namedCurve, ?secp256k1}}}) ->
        public_key:compute_key(PubKey, PrivKey)
    end.

%% @doc Store the given keys in a given filename. The keypair is
%% converted to binary keys_to_bin
%%
%% @see keys_to_bin/1
-spec save_keys(key_map(), string()) -> ok | {error, term()}.
save_keys(KeysMap, FileName) when is_list(FileName) ->
    Bin = keys_to_bin(KeysMap),
    file:write_file(FileName, Bin).

%% @doc Convert a given key map to a binary representation that can be
%% saved to file.
-spec keys_to_bin(key_map()) -> binary().
keys_to_bin(Keys = #{secret := {ecc_compact, PrivKey}, public := {ecc_compact, _PubKey}}) ->
    #'ECPrivateKey'{privateKey = PrivKeyBin, publicKey = PubKeyBin} = PrivKey,
    NetType = from_network(maps:get(network, Keys, mainnet)),
    %% public_key produces a private key with its leading zero bytes stripped.
    PaddedPrivKeyBin = pad_ecc_256_scalar(PrivKeyBin),
    <<NetType:4, ?KEYTYPE_ECC_COMPACT:4, PaddedPrivKeyBin:32/binary, PubKeyBin:65/binary>>;
keys_to_bin(Keys = #{secret := {ed25519, PrivKey}, public := {ed25519, PubKey}}) ->
    NetType = from_network(maps:get(network, Keys, mainnet)),
    <<NetType:4, ?KEYTYPE_ED25519:4, PrivKey:64/binary, PubKey:32/binary>>;
keys_to_bin(Keys = #{secret := {secp256k1, PrivKey}, public := {secp256k1, _PubKey}}) ->
    #'ECPrivateKey'{privateKey = PrivKeyBin, publicKey = PubKeyBin} = PrivKey,
    NetType = from_network(maps:get(network, Keys, mainnet)),
    %% public_key produces a private key with its leading zero bytes stripped.
    PaddedPrivKeyBin = pad_ecc_256_scalar(PrivKeyBin),
    <<NetType:4, ?KEYTYPE_SECP256K1:4, PaddedPrivKeyBin:32/binary, PubKeyBin:65/binary>>.

%% @doc Convers a given binary to a key map
-spec keys_from_bin(binary()) -> key_map().

%% Support the Helium Rust wallet format, which deviates from this Erlang
%% implementation in two important ways:
%%     1. It duplicates the network and key type just before the public key.
%%     2. For those key types which are compressible, it compresses the public
%%        key.
keys_from_bin(
    <<NetType:4, ?KEYTYPE_ECC_COMPACT:4, PrivKey:32/binary, NetType:4, ?KEYTYPE_ECC_COMPACT:4,
        PubKeyX:32/binary>>
) ->
    {#'ECPoint'{point = PubKeyBin}, _} = ecc_compact:recover_compact_key(PubKeyX),
    keys_from_bin(<<NetType:4, ?KEYTYPE_ECC_COMPACT:4, PrivKey:32/binary, PubKeyBin:65/binary>>);
keys_from_bin(
    <<NetType:4, ?KEYTYPE_ED25519:4, PrivKey:64/binary, NetType:4, ?KEYTYPE_ED25519:4,
        PubKey:32/binary>>
) ->
    keys_from_bin(<<NetType:4, ?KEYTYPE_ED25519:4, PrivKey/binary, PubKey/binary>>);
keys_from_bin(
    <<NetType:4, ?KEYTYPE_SECP256K1:4, PrivKey:32/binary, NetType:4, ?KEYTYPE_SECP256K1:4,
        PubKeyC:33/binary>>
) ->
    {#'ECPoint'{point = PubKeyBin}, _} = ecc_compact:recover_compressed_key(PubKeyC),
    keys_from_bin(<<NetType:4, ?KEYTYPE_SECP256K1:4, PrivKey:32/binary, PubKeyBin:65/binary>>);

%% These routines follow the established storage conventions that have been 
%% used in this (Erlang) library.
keys_from_bin(
    <<NetType:4, ?KEYTYPE_ECC_COMPACT:4, PrivKeyBin:32/binary, PubKeyBin:65/binary>>
) ->
    Params = {namedCurve, ?secp256r1},
    %% Erlang public_key prefers to store private key scalars with their
    %% leading zero bytes removed.
    ReducedPrivKeyBin = reduce_ecc_256_scalar(PrivKeyBin),
    PrivKey = #'ECPrivateKey'{
        version = 1,
        parameters = Params,
        privateKey = ReducedPrivKeyBin,
        publicKey = PubKeyBin
    },
    PubKey = {#'ECPoint'{point = PubKeyBin}, Params},
    #{
        secret => {ecc_compact, PrivKey},
        public => {ecc_compact, PubKey},
        network => to_network(NetType)
    };
keys_from_bin(<<NetType:4, ?KEYTYPE_ED25519:4, PrivKey:64/binary, PubKey:32/binary>>) ->
   #{
        secret => {ed25519, PrivKey},
        public => {ed25519, PubKey},
        network => to_network(NetType)
    };
keys_from_bin(
    <<NetType:4, ?KEYTYPE_SECP256K1:4, PrivKeyBin:32/binary, PubKeyBin:65/binary>>
) ->
    Params = {namedCurve, ?secp256k1},
    %% Erlang public_key prefers to store private key scalars with their
    %% leading zero bytes removed.
    ReducedPrivKeyBin = reduce_ecc_256_scalar(PrivKeyBin),
    PrivKey = #'ECPrivateKey'{
        version = 1,
        parameters = Params,
        privateKey = ReducedPrivKeyBin,
        publicKey = PubKeyBin
    },
    PubKey = {#'ECPoint'{point = PubKeyBin}, Params},
    #{
        secret => {secp256k1, PrivKey},
        public => {secp256k1, PubKey},
        network => to_network(NetType)
    }.

%% @doc Converts a a given tagged public key to its binary form on the current
%% network.
-spec pubkey_to_bin(pubkey()) -> pubkey_bin().
pubkey_to_bin(PubKey) ->
    pubkey_to_bin(get_network(mainnet), PubKey).

%% @doc Converts a given tagged public key to its binary form on the given
%% network.
-spec pubkey_to_bin(network(), pubkey()) -> pubkey_bin().
pubkey_to_bin(Network, {ecc_compact, PubKey}) ->
    case ecc_compact:is_compact(PubKey) of
        {true, CompactKey} ->
            <<(from_network(Network)):4, ?KEYTYPE_ECC_COMPACT:4, CompactKey/binary>>;
        false ->
            erlang:error(not_compact)
    end;
pubkey_to_bin(Network, {ed25519, PubKey}) ->
    <<(from_network(Network)):4, ?KEYTYPE_ED25519:4, PubKey/binary>>;
pubkey_to_bin(Network, {multisig, M, N, KeysDigest}) ->
    <<
        (from_network(Network)):4,
        ?KEYTYPE_MULTISIG:4,
        M:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
        N:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
        KeysDigest/binary
    >>;
pubkey_to_bin(Network, {secp256k1, PubKey}) ->
    %% Compress the public key point
    {#'ECPoint'{point=PubPoint}, _Params} = PubKey,
    CompressedPoint = compress_ecc_256_point(PubPoint),
    <<(from_network(Network)):4, ?KEYTYPE_SECP256K1:4, CompressedPoint:33/binary>>.

%% @doc Converts a a given binary encoded public key to a tagged public
%% key. The key is asserted to be on the current active network.
-spec bin_to_pubkey(pubkey_bin()) -> pubkey().
bin_to_pubkey(PubKeyBin) ->
    bin_to_pubkey(get_network(mainnet), PubKeyBin).

%% @doc Converts a a given binary encoded public key to a tagged public key. If
%% the given binary is not on the specified network a bad_network is thrown.
-spec bin_to_pubkey(network(), pubkey_bin()) -> pubkey().
bin_to_pubkey(Network, <<NetType:4, ?KEYTYPE_ECC_COMPACT:4, PubKey:32/binary>>) ->
    case NetType == from_network(Network) of
        true -> {ecc_compact, ecc_compact:recover_compact_key(PubKey)};
        false -> erlang:error({bad_network, NetType})
    end;
bin_to_pubkey(Network, <<NetType:4, ?KEYTYPE_ED25519:4, PubKey:32/binary>>) ->
    case NetType == from_network(Network) of
        true -> {ed25519, PubKey};
        false -> erlang:error({bad_network, NetType})
    end;
bin_to_pubkey(
    Network,
    <<
        NetType:4,
        ?KEYTYPE_MULTISIG:4,
        M:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
        N:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
        KeysDigest/binary
    >>
) ->
    case NetType == from_network(Network) of
        true ->
            case M =< N of
                true ->
                    case multihash:hash(KeysDigest) of
                        {error, Reason} ->
                            erlang:error({bad_multihash, Reason});
                        {ok, _} ->
                            {multisig, M, N, KeysDigest}
                    end;
                false ->
                    erlang:error({m_higher_than_n, M, N})
            end;
        false -> erlang:error({bad_network, NetType})
    end;
bin_to_pubkey(Network, <<NetType:4, ?KEYTYPE_SECP256K1:4, ComprPubKey:33/binary>>) ->
    case NetType == from_network(Network) of
        true -> {secp256k1, ecc_compact:recover_compressed_key(ComprPubKey)};
        false -> erlang:error({bad_network, NetType})
    end.

%% @doc Converts a public key to base58 check encoded string
%% on the currently active network.
-spec pubkey_to_b58(pubkey()) -> string().
pubkey_to_b58(PubKey) ->
    pubkey_to_b58(get_network(mainnet), PubKey).

%% @doc Converts a public key to base58 check encoded string on the given
%% network.
-spec pubkey_to_b58(network(), pubkey()) -> string().
pubkey_to_b58(Network, PubKey) ->
    bin_to_b58(pubkey_to_bin(Network, PubKey)).

%% @doc Converts a base58 check encoded string to a public key.
%% The public key is asserted to be on the currently active network.
-spec b58_to_pubkey(string()) -> pubkey().
b58_to_pubkey(Str) ->
    b58_to_pubkey(get_network(mainnet), Str).

%% @doc Converts a base58 check encoded string to a public key.
%% The public key is asserted to be on the given network.
-spec b58_to_pubkey(network(), string()) -> pubkey().
b58_to_pubkey(Network, Str) ->
    bin_to_pubkey(Network, b58_to_bin(Str)).

%% @doc Convert mainnet or testnet to its tag nibble
-spec from_network(network()) -> ?NETTYPE_MAIN | ?NETTYPE_TEST.
from_network(mainnet) -> ?NETTYPE_MAIN;
from_network(testnet) -> ?NETTYPE_TEST.

%% @doc Convert a testnet nibble to mainnet or testnet.
-spec to_network(?NETTYPE_MAIN | ?NETTYPE_TEST) -> network().
to_network(?NETTYPE_MAIN) -> mainnet;
to_network(?NETTYPE_TEST) -> testnet.

-spec key_size_bytes(non_neg_integer()) -> pos_integer().
key_size_bytes(?KEYTYPE_ED25519) ->
    32;
key_size_bytes(?KEYTYPE_ECC_COMPACT) ->
    32;
key_size_bytes(?KEYTYPE_SECP256K1) ->
    33;
key_size_bytes(KeyType) ->
    error({bad_key_type, KeyType}).

%% @doc Verifies a binary against a given digital signature.
-spec verify(binary(), binary(), pubkey()) -> boolean().
verify(Bin, MultiSignature, {multisig, M, N, KeysDigest}) ->
    HashTypes = ?MULTI_HASH_TYPES_SUPPORTED ++ ?MULTI_HASH_TYPES_DEPRECATED,
    verify_multisig(Bin, MultiSignature, {multisig, M, N, KeysDigest}, HashTypes);
verify(Bin, Signature, {ecc_compact, PubKey}) ->
    public_key:verify(Bin, sha256, Signature, PubKey);
verify(Bin, Signature, {ed25519, PubKey}) ->
    enacl:sign_verify_detached(Signature, Bin, PubKey);
verify(Bin, Signature, {secp256k1, PubKey}) ->
    public_key:verify(Bin, sha256, Signature, PubKey).

-spec verify_multisig(binary(), binary(), pubkey_multi(), [atom()]) -> boolean().
verify_multisig(Bin, MultiSignature, {multisig, M, N, KeysDigest}, HashTypes) ->
    verify_multisig(get_network(mainnet), Bin, MultiSignature, {multisig, M, N, KeysDigest}, HashTypes).

-spec verify_multisig(network(), binary(), binary(), pubkey_multi(), [atom()]) -> boolean().
verify_multisig(Network, Bin, MultiSignature, {multisig, M, N, KeysDigest}, HashTypes) ->
    try
        {Keys, KeysLen} = multisig_parse_keys(Network, MultiSignature, N),
        N = length(Keys),
        <<KeysBin:KeysLen/binary, ISigsBin/binary>> = MultiSignature,
        case multihash:hash(KeysDigest) of
            {error, _} ->
                false;
            {ok, HashType} ->
                case lists:member(HashType, HashTypes) of
                    true ->
                        case multihash:digest(KeysBin, HashType) of
                            {ok, <<KeysDigest/binary>>} ->
                                ISigs = multisig_parse_isigs(ISigsBin, M, N),
                                %% Reject dup key index
                                case ISigs -- lists:ukeysort(1, ISigs) of
                                    [] ->
                                        %% Index range: 0..N-1
                                        KS = [{lists:nth(I + 1, Keys), S} || {I, S} <- ISigs],
                                        M =< length([{} || {K, S} <- KS, verify(Bin, S, K)]);
                                    [_|_] ->
                                        false
                                end;
                            _ ->
                                false
                        end;
                    false ->
                        false
                end
        end
    catch _:_ ->
              false
    end.

-spec multisig_parse_keys(network(), binary(), non_neg_integer()) ->
    {[pubkey()], non_neg_integer()}.
multisig_parse_keys(Network, <<MultiSignature/binary>>, N) ->
    multisig_parse_keys(Network, MultiSignature, N, 0, []).

-spec multisig_parse_keys(network(), binary(), non_neg_integer(), non_neg_integer(), [pubkey()]) ->
    {[pubkey()], non_neg_integer()}.
multisig_parse_keys(Network, <<_/binary>>, 0, ConsumedBytes, Keys) ->
    {multisig_member_keys_sort(Network, Keys), ConsumedBytes};
multisig_parse_keys(Network, <<NetType:4, KeyType:4, Rest0/binary>>, N, ConsumedBytes0, Keys) ->
    Size = key_size_bytes(KeyType),
    <<KeyBin:Size/bytes, Rest1/binary>> = Rest0,
    Key = bin_to_pubkey(to_network(NetType), <<NetType:4, KeyType:4, KeyBin:Size/binary>>),
    ConsumedBytes1 = ConsumedBytes0 + 1 + Size, % 1 for (NetType + KeyType)
    multisig_parse_keys(Network, Rest1, N - 1, ConsumedBytes1, [Key | Keys]);
multisig_parse_keys(_, <<_/binary>>, _, _, _) ->
    erlang:error(multisig_keys_misaligned).

-spec multisig_parse_isigs(binary(), pos_integer(), pos_integer()) ->
    [{non_neg_integer(), binary()}].
multisig_parse_isigs(<<ISigsBin/binary>>, M, N) ->
    multisig_parse_isigs(ISigsBin, M, N, []).

multisig_parse_isigs(<<>>, _, _, ISigs) ->
    ISigs;
multisig_parse_isigs(
    <<I:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
      ByteLen:?MULTISIG_SIG_LEN_BYTES/integer-unsigned-little,
      Rest0/binary>>,
    M,
    N,
    ISigs
) ->
    %% Indices are in the range 0..N-1
    case I >= N of
        true ->
            erlang:error({multisig_parse_isigs, invalid_index});
        false ->
            <<Sig:ByteLen/binary, Rest1/binary>> = Rest0,
            multisig_parse_isigs(Rest1, M, N, [{I, Sig} | ISigs])
    end;
multisig_parse_isigs(<<_/binary>>, _, _, _) ->
    erlang:error({multisig_parse_isigs, misaligned}).

%% @doc Convert a binary to a base58 check encoded string. The encoded
%% version is set to 0.
%%
%% @see bin_to_b58/2
-spec bin_to_b58(binary()) -> string().
bin_to_b58(Bin) ->
    bin_to_b58(16#00, Bin).

%% @doc Convert a binary to a base58 check encoded string
-spec bin_to_b58(non_neg_integer(), binary()) -> string().
bin_to_b58(Version, Bin) ->
    base58check_encode(Version, Bin).

%% @doc Convert a base58 check encoded string to the original
%% binary.The version encoded in the base58 encoded string is ignore.
%%
%% @see b58_to_version_bin/1
-spec b58_to_bin(string()) -> binary().
b58_to_bin(Str) ->
    {_, Addr} = b58_to_version_bin(Str),
    Addr.

%% @doc Decodes a base58 check ecnoded string into it's version and
%% binary parts.
-spec b58_to_version_bin(string()) -> {Version :: non_neg_integer(), Bin :: binary()}.
b58_to_version_bin(Str) ->
    case base58check_decode(Str) of
        {ok, <<Version:8/unsigned-integer>>, Bin} -> {Version, Bin};
        {error, Reason} -> error(Reason)
    end.

%% @doc Converts a given binary public key to a P2P address.
%%
%% @see p2p_to_pubkey_bin/1
-spec pubkey_bin_to_p2p(pubkey_bin()) -> string().
pubkey_bin_to_p2p(PubKey) when is_binary(PubKey) ->
    "/p2p/" ++ bin_to_b58(PubKey).

%% @doc Takes a P2P address and decodes it to a binary public key
-spec p2p_to_pubkey_bin(string()) -> pubkey_bin().
p2p_to_pubkey_bin(Str) ->
    case multiaddr:protocols(Str) of
        [{"p2p", B58Addr}] -> b58_to_bin(B58Addr);
        _ -> error(badarg)
    end.

-spec base58check_encode(non_neg_integer(), binary()) -> string().
base58check_encode(Version, Payload) when Version >= 0, Version =< 16#FF ->
    VPayload = <<Version:8/unsigned-integer, Payload/binary>>,
    <<Checksum:4/binary, _/binary>> = crypto:hash(sha256, crypto:hash(sha256, VPayload)),
    Result = <<VPayload/binary, Checksum/binary>>,
    base58:binary_to_base58(Result).

-spec base58check_decode(string()) -> {'ok', <<_:8>>, binary()} | {error, bad_checksum}.
base58check_decode(B58) ->
    Bin = base58:base58_to_binary(B58),
    PayloadSize = byte_size(Bin) - 5,
    <<Version:1/binary, Payload:PayloadSize/binary, Checksum:4/binary>> = Bin,
    %% validate the checksum
    case crypto:hash(sha256, crypto:hash(sha256, <<Version/binary, Payload/binary>>)) of
        <<Checksum:4/binary, _/binary>> ->
            {ok, Version, Payload};
        _ ->
            {error, bad_checksum}
    end.

-spec pubkey_is_multisig(pubkey()) -> boolean().
pubkey_is_multisig({multisig, _, _, _}) ->
    true;
pubkey_is_multisig({ecc_compact, _}) ->
    false;
pubkey_is_multisig({ed25519, _}) ->
    false;
pubkey_is_multisig({secp256k1, _}) ->
    false.

%% @doc The binary form of this multisig-pubkey can be optained with
%% pubkey_to_bin (just as any other pubkey), the format of which will be
%% roughly:
%%
%%     <<NetType:4, KeyType:4, M/integer, N/integer, KeysDigest/binary>>
%%
%% (for precise sizes and KeyType value, see: bin_to_pubkey and pubkey_to_bin)
%% @end
-spec make_multisig_pubkey(network(), pos_integer(), pos_integer(), [pubkey()]) ->
    {ok, binary()} | {error, Error} when
    Error :: {contains_multisig_keys, [pubkey()]}.
make_multisig_pubkey(Network, M, N, PubKeys) ->
    make_multisig_pubkey(Network, M, N, PubKeys, ?MULTI_HASH_TYPE_DEFAULT).

-spec make_multisig_pubkey(network(), pos_integer(), pos_integer(), [pubkey()], HashType) ->
    {ok, binary()} | {error, Error} when
    Error ::
        {contains_multisig_keys, [pubkey()]}
        | {hash_type_unknown, HashType}
        | {hash_type_unsupported, HashType},
    HashType :: atom().
make_multisig_pubkey(Network, M, N, PubKeys, HashType) ->
    case lists:member(HashType, ?MULTI_HASH_TYPES_ALL) of
        true ->
            case lists:member(HashType, ?MULTI_HASH_TYPES_SUPPORTED) of
                true ->
                    make_multisig_pubkey_(Network, M, N, PubKeys, HashType);
                false ->
                    {error, {hash_type_unsupported, HashType}}
            end;
        false ->
            {error, {hash_type_unknown, HashType}}
    end.

-spec make_multisig_pubkey_(network(), pos_integer(), pos_integer(), [pubkey()], HashType) ->
    {ok, binary()} | {error, Error} when
    Error :: {contains_multisig_keys, [pubkey()]}
        | {multihash_failure, Reason :: term()},
    HashType :: atom().
make_multisig_pubkey_(Network, M, N, PubKeys, HashType) ->
    case lists:filter(fun pubkey_is_multisig/1, PubKeys) of
        [_|_]=PKs ->
            {error, {contains_multisig_keys, PKs}};
        [] ->
            PubKeysBin = multisig_member_keys_to_bin(Network, PubKeys),
            case multihash:digest(PubKeysBin, HashType) of
                {ok, <<KeysDigest/binary>>} ->
                    {ok, {multisig, M, N, KeysDigest}};
                {error, Reason} ->
                    {error, {multihash_failure, Reason}}
            end
    end.

-spec multisig_member_keys_to_bin(network(), [pubkey_single()]) -> binary().
multisig_member_keys_to_bin(Net, PKs) ->
    Bins = [pubkey_to_bin(Net, K) || K <- multisig_member_keys_sort(Net, PKs)],
    iolist_to_binary(Bins).

-spec multisig_member_key_index(pubkey_single(), [pubkey_single()]) ->
    non_neg_integer().
multisig_member_key_index(Key, Keys) ->
    multisig_member_key_index(get_network(mainnet), Key, Keys).

-spec multisig_member_key_index(network(), pubkey_single(), [pubkey_single()]) ->
    non_neg_integer().
multisig_member_key_index(Network, Key, Keys0) ->
    N = length(Keys0),
    Keys1 = multisig_member_keys_sort(Network, Keys0),
    case [I || {I, K} <- lists:zip(lists:seq(0, N - 1), Keys1), K == Key] of
        [I] -> I;
        []  -> erlang:error(key_not_in_given_list)
    end.

-spec multisig_member_keys_sort([pubkey_single()]) -> [pubkey_single()].
multisig_member_keys_sort(Keys) ->
    multisig_member_keys_sort(get_network(mainnet), Keys).

-spec multisig_member_keys_sort(network(), [pubkey_single()]) -> [pubkey_single()].
multisig_member_keys_sort(Network, Keys0) ->
    Keys1 = [{K, multisig_member_key_sort_form(Network, K)} || K <- Keys0],
    Cmp = fun ({_, A}, {_, B}) -> multisig_member_keys_cmp(A, B) end,
    [K || {K, _} <- lists:sort(Cmp, Keys1)].

-spec multisig_member_keys_cmp(binary(), binary()) -> boolean().
multisig_member_keys_cmp(A, B) ->
    A < B.

-spec multisig_member_key_sort_form(network(), pubkey_single()) -> binary().
multisig_member_key_sort_form(_, {multisig, _, _, _}) ->
    erlang:error({badarg, expected_single_but_given_multisig_pubkey});
multisig_member_key_sort_form(Network, PK) ->
    list_to_binary(pubkey_to_b58(Network, PK)).

%% @doc A multisig-signature is a concatanation of a list of N
%% individual-pubkeys and a list of M-N triples of individual-signatures
%% prefixed with an index (of corresponsing individual-pubkey in the
%% multisig-pubkey) and the length of the individual-signature:
%%
%% <<PubKeys/binary, Triples/binary>>
%% where
%% Pubkeys = <<PK0/binary, ..., PKN/binary>>
%% Triples =
%%   <<
%%     0/integer, Len0/integer Sig0:Len0/binary,
%%     ...,
%%     N/integer, LenN/integer, SigN/binary
%%   >>
%%
%% (see for precise sizes see: isig_to_bin, multisig_parse_isigs)
%%
%% PubKeys MUST be in the same order as when each signature-triple was constructed.
%% Signature-triples MAY be in any order.
%% @end
-spec make_multisig_signature(
    network(),
    binary(),
    pubkey_multi(),
    [pubkey_single()],
    [{non_neg_integer(), binary()}]
) -> {ok, binary()} | {error, Error} when
    Error ::
        insufficient_signatures
        | insufficient_keys
        | too_many_keys
        | bad_key_digest
        | {invalid_signatures, [binary()]}.
make_multisig_signature(_, _, {multisig, M, _, _}, _, S) when M > length(S) ->
    {error, insufficient_signatures};
make_multisig_signature(_, _, {multisig, _, N, _}, K, _) when N > length(K) ->
    {error, insufficient_keys};
make_multisig_signature(_, _, {multisig, _, N, _}, K, _) when N < length(K) ->
    {error, too_many_keys};
make_multisig_signature(Network, Msg, {multisig, _, _, KeysDigest}, Keys0, ISigs) ->
    {ok, HashType} = multihash:hash(KeysDigest),
    Keys = multisig_member_keys_sort(Network, Keys0),
    KeysBin = multisig_member_keys_to_bin(Network, Keys),
    case multihash:digest(KeysBin, HashType) of
        {ok, <<KeysDigest/binary>>} ->
            KeySigs = [{lists:nth(I + 1, Keys), S} || {I, S} <- ISigs],
            case [S || {K, S} <- KeySigs, not verify(Msg, S, K)] of
                [] ->
                    ISigsBins = lists:map(fun isig_to_bin/1, ISigs),
                    {ok, iolist_to_binary([KeysBin, ISigsBins])};
                [_|_]=Sigs ->
                    {error, {invalid_signatures, Sigs}}
            end;
        {ok, <<_/binary>>} ->
            {error, bad_key_digest};
        {error, _} ->
            {error, bad_key_digest}
    end.

-spec isig_to_bin({non_neg_integer(), binary()}) -> binary().
isig_to_bin({I, <<Sig/binary>>}) ->
    Len = byte_size(Sig),
    <<
        I:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
        Len:?MULTISIG_SIG_LEN_BYTES/integer-unsigned-little,
        Sig/binary
    >>.

%% Consistently pad a private key scalar so that it is always 32 bytes.
-spec pad_ecc_256_scalar(binary()) -> binary().
pad_ecc_256_scalar(<<NoPadNeeded:32/binary>>) ->
    NoPadNeeded;
pad_ecc_256_scalar(<<NeedsPadding/binary>>) ->
    BytesShort = 32 - byte_size(NeedsPadding),
    ZeroBytes = <<0:(BytesShort*8)>>,
    <<ZeroBytes/binary, NeedsPadding/binary>>.

%% Remove leading zero bytes from a big-endian bignum buffer
-spec reduce_ecc_256_scalar(binary()) -> binary().
reduce_ecc_256_scalar(<<0, BigNum/binary>>) ->
    reduce_ecc_256_scalar(BigNum);
reduce_ecc_256_scalar(<<BigNum/binary>>) ->
    BigNum.

%% Compute a point tag (the integer 2 or 3) to represent the compressed
%% Y coordinate for a 256-bit elliptic curve point.
-spec point_tag_for_ecc_256_scalar(binary()) -> non_neg_integer().
point_tag_for_ecc_256_scalar(<<_Upper:31/binary, Bottom:8/unsigned-integer>>) ->
    2 + (Bottom rem 2).

%% Compress an elliptic curve point.
-spec compress_ecc_256_point(binary()) -> binary().
compress_ecc_256_point(<<TaggedPoint:65/binary>>) ->
    <<4, XCoordinate:32/binary, YCoordinate:32/binary>> = TaggedPoint,
    Tag = point_tag_for_ecc_256_scalar(YCoordinate),
    <<Tag, XCoordinate/binary>>.

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

%% @doc Generates an EUnit test-set from the given parameters.
%% For test-set representation details see:
%% http://erlang.org/doc/apps/eunit/chapter.html#eunit-test-representation
%% @end
make_multisig_test_cases(Network, M, N, KeyType0, HashType, HashTypes) ->
    Title =
        fun (Name) ->
            lists:flatten(io_lib:format(
                "Multisig test: ~s. Params: [Network: ~p, M:~b, N:~b, KeyType:~p, HashType:~s, HashTypes: ~p].",
                [Name, Network, M, N, KeyType0, HashType, HashTypes]
             ))
        end,
    MsgGood = <<"I'm in dire need of HNT and communications to reach others seem abortive.">>,
    ISigsToBin = fun (ISigs) -> lists:map(fun isig_to_bin/1, ISigs) end,
    KeySig =
        fun () ->
                #{secret := S, public := P} =
                    case KeyType0 of
                        random ->
                            generate_keys(list_random_element(?PRIMITIVE_KEY_TYPES));
                        {specific, KeyType} ->
                            generate_keys(KeyType)
                    end,
            {P, (mk_sig_fun(S))(MsgGood)}
        end,
    KeySigs = [KeySig() || _ <- lists:duplicate(N, {})],
    Keys0 = [K || {K, _} <- KeySigs],
    ISigs0 = [{multisig_member_key_index(Network, K, Keys0), S} || {K, S} <- KeySigs],
    ISigs = list_shuffle(lists:sublist(ISigs0, M)),
    PK2Bin = fun(PK) -> pubkey_to_bin(Network, PK) end,
    BinKeys = lists:map(PK2Bin, Keys0),
    {ok, KeysDigest} = multihash:digest(iolist_to_binary(BinKeys), HashType),
    {ok, MultiPubKeyGood} = make_multisig_pubkey_(Network, M, N, Keys0, HashType),
    {ok, MultiSigGood} = make_multisig_signature(Network, MsgGood, MultiPubKeyGood, Keys0, ISigs),

    Positive =
        [
            %% pubkey
            {
                Title("pubkey serialization round trip"),
                ?_assertEqual(MultiPubKeyGood, bin_to_pubkey(Network, PK2Bin(MultiPubKeyGood)))
            },
            {
                Title("pubkey_is_multisig"),
                ?_assert(pubkey_is_multisig(MultiPubKeyGood))
            },
            {
                Title("pubkey multihash support check"),
                case lists:member(HashType, ?MULTI_HASH_TYPES_SUPPORTED) of
                    true ->
                        ?_assertEqual(
                            {ok, MultiPubKeyGood},
                            make_multisig_pubkey(Network, M, N, Keys0, HashType)
                        );
                    false ->
                        ?_assertEqual(
                            {error, {hash_type_unsupported, HashType}},
                            make_multisig_pubkey(Network, M, N, Keys0, HashType)
                        )
                end
            },

            %% sig
            {
                Title("Everything validly constructed"),
                ?_assert(verify_multisig(Network, MsgGood, MultiSigGood, MultiPubKeyGood, HashTypes))
            }
        ],
    Negative =
        [
            (fun() ->
                HT = trust_me_im_a_valid_hash_type,
                ?_assertEqual(
                    {error, {hash_type_unknown, HT}},
                    make_multisig_pubkey(Network, M, N, Keys0, HT)
                )
            end)(),
            ?_assertEqual(
                {error, insufficient_signatures},
                make_multisig_signature(
                    Network,
                    MsgGood,
                    MultiPubKeyGood,
                    Keys0,
                    lists:sublist(ISigs, M - 1)
                )
            ),
            ?_assertEqual(
                {error, insufficient_keys},
                make_multisig_signature(
                    Network,
                    MsgGood,
                    MultiPubKeyGood,
                    lists:sublist(Keys0, M - 1),
                    ISigs
                )
            ),
            ?_assertEqual(
                {error, too_many_keys},
                make_multisig_signature(
                    Network,
                    MsgGood,
                    MultiPubKeyGood,
                    lists:duplicate(N + 1, hd(Keys0)),
                    ISigs
                )
            ),
            {
                Title("make_multisig_signature with a wrong member key"),
                ?_assertEqual(
                    {error, bad_key_digest},
                    %% To hit this exact error we need valid:
                    %% - M
                    %% - N
                    %% - hash function and type
                    %% - key formats
                    %% - key count
                    %% BUT at least one of the member keys to be different from
                    %% what we expect:
                    make_multisig_signature(
                        Network,
                        MsgGood,
                        {multisig, M, N,
                            (fun() ->
                                {PK, _} = KeySig(),
                                {ok, BadKeysDigest} =
                                    multihash:digest(
                                        iolist_to_binary([pubkey_to_bin(Network, PK) | tl(BinKeys)]),
                                        HashType
                                    ),
                                BadKeysDigest
                            end)()
                        },
                        Keys0,
                        ISigs
                    )
                )
            },
            {
                Title("Break index on a random isig, by pushing it out of range"),
                (fun () ->
                    R = rand:uniform(M) - 1, % Correct for 0-index
                    Replace =
                        fun ({I, S}) when I =:= R -> {N + 1, S}; (IS) -> IS end,
                    ISigsOutOfRange = lists:map(Replace, ISigs),
                    SigBad = iolist_to_binary([BinKeys, ISigsToBin(ISigsOutOfRange)]),
                    ?_assertNot(verify_multisig(Network, MsgGood, SigBad, MultiPubKeyGood, HashTypes))
                end)()
            },
            {
                Title("Duplicate sig from same index"),
                (fun () ->
                    SigBad = iolist_to_binary([BinKeys, ISigsToBin([hd(ISigs)|ISigs])]),
                    ?_assertNot(verify_multisig(Network, MsgGood, SigBad, MultiPubKeyGood, HashTypes))
                end)()
            },
            {
                Title("Unsupported hash type"),
                (fun () ->
                    {ok, MultiPubKeyBad} = make_multisig_pubkey_(Network, M, N, Keys0, HashType),
                    {ok, SigBad} = make_multisig_signature(Network, MsgGood, MultiPubKeyBad, Keys0, ISigs),
                    ?_assertNot(verify_multisig(Network, MsgGood, SigBad, MultiPubKeyBad, HashTypes -- [HashType]))
                end)()
            },
            {
                Title("Wrong message string"),
                ?_assertNot(verify_multisig(
                    Network,
                    <<MsgGood/binary, "totally not a scam">>,
                    MultiSigGood,
                    MultiPubKeyGood,
                    HashTypes
                ))
            },
            {
                Title("Multisig with appended junk"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    <<MultiSigGood/binary, "looks legit">>,
                    MultiPubKeyGood,
                    HashTypes
                ))
            },
            {
                Title("Multisig with unsupported hash"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    multihash:digest(iolist_to_binary(BinKeys), sha1),
                    MultiPubKeyGood,
                    HashTypes
                ))
            },
            {
                Title("Pubkey with junk appended to keys digest"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    MultiSigGood,
                    {multisig, M, N, <<KeysDigest/binary, "hi">>},
                    HashTypes
                ))
            },
            {
                Title("Pubkey M > N"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    MultiSigGood,
                    {multisig, N + 1, N, KeysDigest},
                    HashTypes
                ))
            },
            {
                Title("Pubkey N < M"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    MultiSigGood,
                    {multisig, M, M - 1, KeysDigest},
                    HashTypes
                ))
            },
            {
                Title("Pubkey M + 1"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    MultiSigGood,
                    {multisig, M + 1, N, KeysDigest},
                    HashTypes
                ))
            },
            {
                Title("Pubkey N + 1"),
                ?_assertNot(verify_multisig(
                    Network,
                    MsgGood,
                    MultiSigGood,
                    {multisig, M, N + 1, KeysDigest},
                    HashTypes
                ))
            },
            {
                Title("bin_to_pubkey bad multihash"),
                ?_assertError(
                    {bad_multihash, invalid_code},
                    bin_to_pubkey(
                        Network,
                        <<
                            (from_network(Network)):4,
                            ?KEYTYPE_MULTISIG:4,
                            3:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                            5:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                            "hello world"
                        >>
                    )
                )
            },
            {
                Title("bin_to_pubkey m higher than N"),
                ?_assertError(
                    {m_higher_than_n, 5, 3},
                    bin_to_pubkey(
                        Network,
                        <<
                            (from_network(Network)):4,
                            ?KEYTYPE_MULTISIG:4,
                            5:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                            3:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                            "hello world"
                        >>
                    )
                )
            },
            {
                Title("bin_to_pubkey bad nettype"),
                (fun() ->
                    [BadNetwork] = [mainnet, testnet] -- [Network],
                    ?_assertError(
                        {bad_network, _},
                        bin_to_pubkey(
                            BadNetwork,
                            <<
                                (from_network(Network)):4,
                                ?KEYTYPE_MULTISIG:4,
                                3:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                                5:?MULTISIG_KEY_INDEX_BITS/integer-unsigned-little,
                                "hello world"
                            >>
                        )
                    )
                 end)()
            }
        ]
        ++
        %% XXX Non-determinism mitigations:
        %% - We PRE-SORT because we can't otherwise be sure if the generated
        %%   keys did not _accidentally_ end up in the correct order;
        %% - We re-order MANUALLY because list_shuffle is not deterministic,
        %%   especially for small lists.
        %% XXX Fragile, since it doesn't use the canonical multisig_member_key_sort_form.
        case lists:sort(fun multisig_member_keys_cmp/2, lists:map(fun bin_to_b58/1, BinKeys)) of
            [K1, K2 | Ks] ->
                [{
                    Title("Re-ordered keys"),
                    ?_assertNot(verify_multisig(
                        Network,
                        MsgGood,
                        iolist_to_binary([[K2, K1 | Ks], ISigsToBin(ISigs)]),
                        MultiPubKeyGood,
                        HashTypes
                    ))
                }];
            [_] ->
                []
        end
        ++
        case M > 1 of
            false ->
                [];
            true ->
                [IS | _] = ISigs,
                SigBad =
                    [iolist_to_binary([BinKeys, ISigsToBin(lists:duplicate(M, IS))])],
                [{
                    Title("Reuse same signature M times"),
                    ?_assertNot(verify_multisig(Network, MsgGood, SigBad, MultiPubKeyGood, HashTypes))
                }]
        end,
    Positive ++ Negative.

multisig_test_() ->
    HashTypes = ?MULTI_HASH_TYPES_ALL,
    Params =
        [
            [Network, M, N, K, H, HashTypes]
        ||
            N <- lists:seq(1, 5),
            M <- lists:seq(1, N),
            H <- HashTypes,
            K <- [random | [{specific, KT} || KT <- ?PRIMITIVE_KEY_TYPES]],
            Network <- [mainnet, testnet]
        ],
    {inparallel, test_generator(fun make_multisig_test_cases/6, Params)}.

save_load_test() ->
    SaveLoad = fun(Network, KeyType) ->
        FileName = nonl(os:cmd("mktemp")),
        Keys = generate_keys(Network, KeyType),
        ok = libp2p_crypto:save_keys(Keys, FileName),
        {ok, LKeys} = load_keys(FileName),
        ?assertEqual(LKeys, Keys)
    end,
    SaveLoad(mainnet, ecc_compact),
    SaveLoad(testnet, ecc_compact),
    SaveLoad(mainnet, ed25519),
    SaveLoad(testnet, ed25519),
    SaveLoad(mainnet, secp256k1),
    SaveLoad(testnet, secp256k1),

    {error, _} = load_keys("no_such_file"),
    ok.

address_test() ->
    Roundtrip = fun(KeyType) ->
        #{public := PubKey} = generate_keys(KeyType),

        PubBin = pubkey_to_bin(PubKey),
        ?assertEqual(PubKey, bin_to_pubkey(PubBin)),

        PubB58 = bin_to_b58(PubBin),

        MAddr = pubkey_bin_to_p2p(PubBin),
        ?assertEqual(PubBin, p2p_to_pubkey_bin(MAddr)),

        ?assertEqual(PubB58, pubkey_to_b58(PubKey)),
        ?assertEqual(PubKey, b58_to_pubkey(PubB58)),

        BadNetwork =
            case get_network(mainnet) of
                mainnet -> testnet;
                testnet -> mainnet
            end,
        ?assertError({bad_network, _}, bin_to_pubkey(BadNetwork, PubBin))
    end,

    Roundtrip(ecc_compact),
    Roundtrip(ed25519),
    Roundtrip(secp256k1),

    set_network(mainnet),
    Roundtrip(ecc_compact),
    Roundtrip(ed25519),
    Roundtrip(secp256k1),

    set_network(testnet),
    Roundtrip(ecc_compact),
    Roundtrip(ed25519),
    Roundtrip(secp256k1),

    ok.

verify_sign_test() ->
    Bin = <<"sign me please">>,
    Verify = fun(KeyType) ->
        #{secret := PrivKey, public := PubKey} = generate_keys(KeyType),
        Sign = mk_sig_fun(PrivKey),
        Signature = Sign(Bin),

        ?assert(verify(Bin, Signature, PubKey)),
        ?assert(not verify(<<"failed...">>, Signature, PubKey))
    end,

    Verify(ecc_compact),
    Verify(ed25519),
    Verify(secp256k1),

    ok.

verify_ecdh_test() ->
    Verify = fun(KeyType) ->
        #{secret := PrivKey1, public := PubKey1} = generate_keys(KeyType),
        #{secret := PrivKey2, public := PubKey2} = generate_keys(KeyType),
        #{secret := _PrivKey3, public := PubKey3} = generate_keys(KeyType),
        ECDH1 = mk_ecdh_fun(PrivKey1),
        ECDH2 = mk_ecdh_fun(PrivKey2),

        ?assertEqual(ECDH1(PubKey2), ECDH2(PubKey1)),
        ?assertNotEqual(ECDH1(PubKey3), ECDH2(PubKey3))
    end,

    Verify(ecc_compact),
    Verify(ed25519),
    Verify(secp256k1),

    ok.

%% erlfmt-ignore
%% Tests that a shortened private scalar, that is, one with at least eight
%% upper bits set to zero, and thus, whose Erlang `public_key` representation
%% is one byte _shorter_ than normal, is nonetheless encoded and decoded
%% properly when converted to "network" order.
round_trip_short_key_test() ->
    ShortKeyMap = #{
        network => mainnet,
        public =>
            {ecc_compact,
                {{'ECPoint',
                        <<4, 2, 151, 174, 89, 188, 129, 160, 76, 74, 234, 246, 22, 24, 16,
                            96, 70, 219, 183, 246, 235, 40, 90, 107, 29, 126, 74, 14, 11,
                            201, 75, 2, 168, 74, 18, 165, 99, 26, 32, 161, 195, 100, 232,
                            40, 130, 76, 231, 85, 239, 255, 213, 129, 210, 184, 181, 233,
                            79, 154, 11, 229, 103, 160, 213, 105, 208>>},
                    {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}},
        secret =>
            {ecc_compact,
                {'ECPrivateKey', 1,
                    %% 31-byte secret scalar, which is shorter than usual.
                    <<49, 94, 129, 63, 91, 89, 3, 86, 29, 23, 158, 86, 76, 180, 129, 140,
                        194, 25, 52, 94, 141, 36, 222, 112, 234, 227, 33, 172, 94, 168,
                        123>>,
                    {namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
                    <<4, 2, 151, 174, 89, 188, 129, 160, 76, 74, 234, 246, 22, 24, 16, 96,
                        70, 219, 183, 246, 235, 40, 90, 107, 29, 126, 74, 14, 11, 201, 75,
                        2, 168, 74, 18, 165, 99, 26, 32, 161, 195, 100, 232, 40, 130, 76,
                        231, 85, 239, 255, 213, 129, 210, 184, 181, 233, 79, 154, 11, 229,
                        103, 160, 213, 105, 208>>}}
    },
    Bin = keys_to_bin(ShortKeyMap),
    ?assertEqual(ShortKeyMap, keys_from_bin(Bin)),
    ok.

%% erlfmt-ignore
helium_wallet_decode_ed25519_test() ->
    FakeTestnetKeyMap = #{
        secret => {ed25519, <<192, 147, 19, 139, 114, 76, 92, 18, 67, 206, 210, 241, 21,
            18, 84, 12, 26, 171, 160, 255, 6, 17, 227, 18, 78, 255, 182, 94, 202, 62, 125,
            50, 75, 192, 49, 183, 242, 203, 231, 180, 84, 235, 178, 8, 57, 34, 132, 195,
            107, 140, 155, 85, 133, 58, 131, 188, 94, 234, 216, 101, 241, 12, 231, 107>>},
        public => {ed25519, <<87, 246, 67, 78, 245, 59, 166, 216, 236, 17, 195, 144, 101,
            96, 188, 112, 178, 183, 80, 75, 195, 218, 46, 184, 175, 181, 131, 207, 236,
            146, 18, 237>>},
        network => testnet
    },
    FakeTestnetKeyPair = <<
        %% Network/type byte (testnet, EDD25519)
         17,
        %% 64-byte private key
        192, 147,  19, 139, 114,  76,  92,  18,  67, 206, 210, 241,  21,  18,  84,  12,
         26, 171, 160, 255,   6,  17, 227,  18,  78, 255, 182,  94, 202,  62, 125,  50,
         75, 192,  49, 183, 242, 203, 231, 180,  84, 235, 178,   8,  57,  34, 132, 195,
        107, 140, 155,  85, 133,  58, 131, 188,  94, 234, 216, 101, 241,  12, 231, 107,
        %% Repeated network/type byte
         17,
        %% 32-byte public key
         87, 246,  67,  78, 245,  59, 166, 216, 236,  17, 195, 144, 101,  96, 188, 112,
        178, 183,  80,  75, 195, 218,  46, 184, 175, 181, 131, 207, 236, 146,  18, 237
    >>,
    KeyMap = keys_from_bin(FakeTestnetKeyPair),
    ?assertEqual(FakeTestnetKeyMap, KeyMap),
    ok.

%% erlfmt-ignore
helium_wallet_decode_ecc_compact_test() ->
    FakeTestnetKeyMap = #{
        network => testnet,
        public =>
            {ecc_compact,{{'ECPoint',
                <<4,35,41,75,130,51,74,141,42, 34,140,61,222,93,12,114,10,
                238,142,214,23,56,70,82,128, 107,100,190,75,80,92,66,106,
                47,99,220,162,215,185,130,211, 86,56,165,149,80,98,123,196,
                188,218,249,171,170,182,108, 247,184,233,199,14,216,41,209,
                36>>},
            {namedCurve,{1,2,840,10045,3,1,7}}}},
      secret =>
          {ecc_compact,{'ECPrivateKey',1,
                <<87,144,91,38,220,189,67,111,253,122,45,167,249,160,253,
                73,145,93,208,112,65,69,89,175,98,89,59,222,68,178,37,
                176>>,
            {namedCurve,{1,2,840,10045,3,1,7}},
                <<4,35,41,75,130,51,74,141,42,34,140,61,222,93,12,114,
                10,238,142,214,23,56,70,82,128,107,100,190,75,80,92,
                66,106,47,99,220,162,215,185,130,211,86,56,165,149,
                80,98,123,196,188,218,249,171,170,182,108,247,184,
                233,199,14,216,41,209,36>>}}},
    FakeTestnetKeyPair =
        <<
        %% network type byte (testnet, ecc_compact)
        16,
        %% 32 byte private key
        87,144,91,38,220,189,67,111,253,122,45,167,249,160,
        253,73,145,93,208,112,65,69,89,175,98,89,59,222,68,178,
        37,176,

        %% repeated type byte
        16,
        %% 32 byte compact public key
        35,41,75,130,51,74,141,42,34,140,61,222,93,12,
        114,10,238,142,214,23,56,70,82,128,107,100,190,75,80,92,
        66,106
        >>,
    KeyMap = keys_from_bin(FakeTestnetKeyPair),
    ?assertEqual(FakeTestnetKeyMap, KeyMap),
    ok.

helium_wallet_decode_secp256k1_test() ->
    SecretScalar =
        <<
        190,128,116,196,254,23,187,15,144,132,151,42,101,25,208,55,
        230,57,95,133,116,49,92,54,145,146,146,146,215,212,156,183
        >>,
    PublicXCoordinate =
        <<
        198,96,223,36,131,163,194,45,123,135,11,238,13,137,233,
        114,248,44,37,248,44,197,12,62,31,23,13,71,195,232,227,145
        >>,
    PublicYCoordinate =
        <<
        21,115,230,18,45,170,107,253,143,215,150,112,246,40,186,123,
        242,186,195,160,11,105,100,162,11,126,33,62,194,111,154,71
        >>,
    TaggedFullPublicPoint =
        <<
        4,  %% Full point-pair tag
        PublicXCoordinate/binary,
        PublicYCoordinate/binary
        >>,
    Curve = {namedCurve,{1,3,132,0,10}},
    FakeTestnetKeyMap = #{
        network => testnet,
        public =>
            {secp256k1,{{'ECPoint', TaggedFullPublicPoint}, Curve}},
      secret =>
          {secp256k1,{'ECPrivateKey', 1, SecretScalar, Curve,
            TaggedFullPublicPoint
            }}},
    FakeTestnetKeyPair =
        <<
        %% network type byte (testnet, secp256k1)
        16#13,
        %% 32 byte private key
        SecretScalar/binary,
        %% repeated type byte
        16#13,
        %% odd-y tag
        3,
        %% 32-byte public X coordinate
        PublicXCoordinate/binary
        >>,
    KeyMap = keys_from_bin(FakeTestnetKeyPair),
    ?assertEqual(FakeTestnetKeyMap, KeyMap),
    ok.

point_compress_even_test() ->
    %% A k256 public key point with an even Y-coordinate.
    EvenYKey =
        <<4,96,208,77,104,198,60,254,164,98,63,137,248,175,65,151,142,
          67,192,223,39,122,40,162,139,152,82,181,33,130,160,232,206,
          210,81,255,21,59,227,197,245,116,226,146,87,254,223,114,215,
          77,82,108,166,10,22,186,72,85,119,155,25,100,141,231,228>>,
    <<4, XCoordinate:32/binary, _YCoordinate:32/binary>> = EvenYKey,
    Expect = <<2, XCoordinate:32/binary>>,
    ?assertEqual(compress_ecc_256_point(EvenYKey), Expect).

point_compress_odd_test() ->
    %% A k256 public key point with an odd Y-coordinate.
    OddYKey =
        <<4,198,148,223,114,141,97,92,50,2,119,52,132,135,74,86,152,
          86,151,212,196,29,141,240,191,206,136,179,113,154,21,246,
          140,47,252,2,53,108,192,138,6,133,162,195,4,177,125,160,200,
          22,102,188,89,214,120,43,115,16,60,225,91,230,34,88,185>>,
    <<4, XCoordinate:32/binary, _YCoordinate:32/binary>> = OddYKey,
    Expect = <<3, XCoordinate:32/binary>>,
    ?assertEqual(compress_ecc_256_point(OddYKey), Expect).

%% Test helpers ===============================================================

nonl([$\n | T]) -> nonl(T);
nonl([H | T]) -> [H | nonl(T)];
nonl([]) -> [].

test_generator(F, Params) ->
    Next =
        fun() ->
            case Params of
                [] -> [];
                [P | Ps] -> [apply(F, P) | test_generator(F, Ps)]
            end
        end,
    {generator, Next}.

-spec array_shuffle(array:array(A)) -> array:array(A).
array_shuffle(A0) ->
    array:foldl(
        fun (I, X, A1) ->
            J = rand:uniform(I + 1) - 1,
            array:set(J, X, array:set(I, array:get(J, A1), A1))
        end,
        array:new(),
        A0
    ).

-spec list_shuffle([A]) -> [A].
list_shuffle(L) ->
    array:to_list(array_shuffle(array:from_list(L))).

-spec list_random_element([A]) -> A.
list_random_element([]) ->
    erlang:error(empty_list);
list_random_element([_|_]=Xs) ->
    lists:nth(rand:uniform(length(Xs)), Xs).

-endif.
