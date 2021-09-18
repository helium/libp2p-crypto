-module(key_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0,
         init_per_testcase/2,
         end_per_testcase/2,
         init_per_group/2,
         end_per_group/2,
         groups/0]).

-export([sig_test/1, roundtrip_test/1]).

test_cases() -> [sig_test, roundtrip_test].

all() ->
    [{group, ecc_compact}, {group, ed25519}, {group, bls12_381}].

groups() ->
    [
        {ecc_compact, [], test_cases()},
        {ed25519, [], test_cases()},
        {bls12_381, [], test_cases()}
    ].

init_per_group(ecc_compact, Config) ->
    [{key_type, ecc_compact} | Config];
init_per_group(ed25519, Config) ->
    [{key_type, ed25519} | Config];
init_per_group(bls12_381, Config) ->
    [{key_type, bls12_381} | Config].

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    Msg = <<"Rip and tear until it's done">>,
    [{total, 43}, {msg, Msg} | Config].

end_per_testcase(_, Config) ->
    Config.

%% Test Cases

roundtrip_test(Config) ->
    true = run_roundtrip_test(gen_keys(Config)),
    true = run_roundtrip_test(gen_keys(Config)),
    true = run_roundtrip_test(gen_keys(Config)),
    ok.

sig_test(Config) ->
    true = run_sig_test(Config, gen_keys(Config)),
    true = run_sig_test(Config, gen_keys(Config)),
    true = run_sig_test(Config, gen_keys(Config)),
    ok.

%% Helpers

run_roundtrip_test(Keys) ->
    Bins = lists:map(fun libp2p_crypto:keys_to_bin/1, Keys),
    B58s = lists:map(fun libp2p_crypto:bin_to_b58/1, Bins),
    Bins1 = lists:map(fun libp2p_crypto:b58_to_bin/1, B58s),
    Bins == Bins1.

gen_keys(Config) ->
    Tot = ?config(total, Config),
    KeyType = ?config(key_type, Config),
    [libp2p_crypto:generate_keys(KeyType) || _ <- lists:seq(1, Tot)].

run_sig_test(Config, Keys) ->
    Msg = ?config(msg, Config),
    SigsAndPKs = lists:map(
                   fun(#{public := PK, secret := SK}) ->
                           SigFun = libp2p_crypto:mk_sig_fun(SK),
                           {SigFun(Msg), PK}
                   end,
                   Keys),

    ct:pal("SigsAndPKs: ~p", [SigsAndPKs]),

    F = fun(SignaturesAndPubkeys) ->
        true = lists:all(
            fun({Sig, PK}) ->
                libp2p_crypto:verify(Msg, Sig, PK)
            end,
            SignaturesAndPubkeys
        )
    end,

    {Time, Res} = timer:tc(F, [SigsAndPKs]),
    ct:pal("Time: ~pms", [Time / 1000]),
    Res.
