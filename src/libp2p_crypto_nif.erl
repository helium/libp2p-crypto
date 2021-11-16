-module(libp2p_crypto_nif).

-on_load(load/0).

-export([load/0, verify/1]).

-spec verify(
    Batch :: [{Bin :: binary(), [{Signature :: binary(), CompactEccKey :: binary()}, ...]}]
) -> ok | {error, Reason :: binary()}.
verify(_Batch) ->
    not_loaded(?LINE).

%% ==================================================================
%% NIF
%% ==================================================================

load() ->
    erlang:load_nif(filename:join(priv(), "libnative"), none).

not_loaded(Line) ->
    erlang:nif_error({error, {not_loaded, [{module, ?MODULE}, {line, Line}]}}).

priv() ->
    case code:priv_dir(?MODULE) of
        {error, _} ->
            EbinDir = filename:dirname(code:which(?MODULE)),
            AppPath = filename:dirname(EbinDir),
            filename:join(AppPath, "priv");
        Path ->
            Path
    end.
