-module(key_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_key_test/0]).

prop_key_test() ->
    ?FORALL(
        {NetType, KeyType, Msg},
        {gen_nettype(), gen_keytype(), gen_msg()},
        begin
            KT = keytype(KeyType),
            Keys = #{secret := PrivKey, public := PubKey} = libp2p_crypto:generate_keys(KT),
            SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
            Signature = SigFun(Msg),

            ToBin = libp2p_crypto:keys_to_bin(Keys),
            KeysFromBin = libp2p_crypto:keys_from_bin(ToBin),

            PubkeyToBin = libp2p_crypto:pubkey_to_bin(NetType, PubKey),
            BinToPubkey = libp2p_crypto:bin_to_pubkey(NetType, PubkeyToBin),

            SignatureCheck = libp2p_crypto:verify(Msg, Signature, PubKey),
            BinCheck = KeysFromBin == Keys,
            PubKeyCheck = BinToPubkey == PubKey,

            ?WHENFAIL(
               begin
                    io:format("KeyType ~p~n", [KeyType]),
                    io:format("NetType ~p~n", [NetType]),
                    io:format("Msg ~p~n", [Msg]),
                    io:format("PubKey ~p~n", [PubKey]),
                    io:format("PrivKey ~p~n", [PrivKey]),
                    io:format("SigFun ~p~n", [SigFun]),
                    io:format("Signature ~p~n", [Signature])
                end,
                conjunction([
                    {valid_pubkey, PubKeyCheck},
                    {valid_bin, BinCheck},
                    {valid_signature, SignatureCheck}
                ])
            )
        end
    ).

gen_nettype() ->
    elements([mainnet, testnet]).

gen_keytype() ->
    elements([0, 1, 3]).

gen_msg() ->
    binary(32).

keytype(0) ->
    ecc_compact;
keytype(1) ->
    ed25519;
keytype(3) ->
    bls12_381.
