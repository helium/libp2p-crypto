-module(key_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([sig_test/1]).

all() -> [sig_test].

init_per_testcase(_, Config) ->
    Msg = <<"Rip and tear until it's done">>,
    [{total, 43}, {msg, Msg} | Config].

end_per_testcase(_, Config) ->
    Config.

sig_test(Config) ->
    Tot = ?config(total, Config),
    true = run(Config, gen_keys(ed25519, Tot)),
    true = run(Config, gen_keys(ecc_compact, Tot)),
    true = run(Config, gen_keys(bls12_381, Tot)),
    ok.

gen_keys(KeyType, Tot) ->
    [libp2p_crypto:generate_keys(KeyType) || _ <- lists:seq(1, Tot)].

run(Config, Keys) ->
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
