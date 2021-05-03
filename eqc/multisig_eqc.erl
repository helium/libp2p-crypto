-module(multisig_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_multipubkey_test/0]).

-define(NETWORK, mainnet).

prop_multipubkey_test() ->
    ?FORALL(
        {KeyType, {M, N}, Msg, HashType},
        {gen_keytype(), gen_m_n(), gen_msg(), gen_hashtype()},
        begin
            KeySig = fun() ->
                #{secret := SK, public := PK} = libp2p_crypto:generate_keys(KeyType),
                {PK, (libp2p_crypto:mk_sig_fun(SK))(Msg)}
            end,
            IKeySigs = [KeySig() || _ <- lists:seq(0, N - 1)],

            Keys0 = [K || {K, _} <- IKeySigs],

            ISigs = lists:sublist([{libp2p_crypto:multisig_member_key_index(K, Keys0), S} || {K, S} <- IKeySigs], M),


            {ok, MultiPubKey} = libp2p_crypto:make_multisig_pubkey(?NETWORK, M, N, Keys0, HashType),
            {ok, MultiSig} = libp2p_crypto:make_multisig_signature(?NETWORK, Msg, MultiPubKey, Keys0, ISigs),

            ?WHENFAIL(
                begin
                    io:format("M ~p~n", [M]),
                    io:format("N ~p~n", [N]),
                    io:format("Msg ~p~n", [Msg]),
                    io:format("MultiPubKey ~p~n", [MultiPubKey]),
                    io:format("MultiSig ~p~n", [MultiSig])
                end,
                conjunction([
                    {valid_pubkey, libp2p_crypto:pubkey_is_multisig(MultiPubKey)},
                    {valid_multipubkey_roundtrip,
                        (MultiPubKey ==
                            libp2p_crypto:bin_to_pubkey(libp2p_crypto:pubkey_to_bin(MultiPubKey)))},
                    {valid_multi_sig, libp2p_crypto:verify(Msg, MultiSig, MultiPubKey)}
                ])
            )
        end
    ).

gen_keytype() ->
    elements([ecc_compact, ed25519]).

gen_m_n() ->
    ?SUCHTHAT({M, N}, {int(), int()}, (N > M andalso N =< 255 andalso M >= 1)).

gen_msg() ->
    binary(32).

%% NOTE: Use this generator if we ever support other hashtypes
gen_hashtype() ->
    elements([
        sha2_256,
        sha3_256,
        blake2b256
    ]).
