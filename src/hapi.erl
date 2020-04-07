%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @doc
%%%
%%% @end
%%% Created : 10 Mar 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi).

%% API
-export([start/0, stop/0]).
-export([get/1, get/2]).
-export([post/1, post/2, post/3]).
-export([format_error/1]).
-export([proxy_status/1]).

-include_lib("kernel/include/inet.hrl").
-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_CONTENT_TYPE, <<"application/json">>).
-define(DNS_TIMEOUT, timer:seconds(5)).
-define(TCP_SEND_TIMEOUT, timer:seconds(5)).
-define(REQ_TIMEOUT, timer:seconds(30)).
-define(RETRY_TIMEOUT, timer:seconds(1)).

-type uri() :: {http, http_uri:user_info(),
                http_uri:host(), inet:port_number(),
                http_uri:path(), http_uri:query()}.
-type req_opts() :: #{timeout => millisecs() | {abs, millisecs()},
                      content_type => binary(),
                      headers => headers(),
                      ip_family => [inet | inet6, ...]}.
-type host_family() :: {http_uri:host(), inet | inet6}.
-type addr_family() :: {inet:ip_address(), inet | inet6}.
-type headers() :: [{binary(), binary()}].
-type req() :: {get, http_uri:path(), http_uri:query(), headers()} |
               {post, http_uri:path(), http_uri:query(), headers(), iodata()}.
-type http_reply() :: {non_neg_integer(), headers(), binary()}.
-type millisecs() :: non_neg_integer().
-type inet_error_reason() :: timeout | closed | inet:posix() | term().
-type error_reason() :: {dns, inet_error_reason()} |
                        {http, inet_error_reason()} |
                        {system_error, term()}.

-export_type([uri/0, error_reason/0, http_reply/0]).

%%%===================================================================
%%% API
%%%===================================================================
-spec start() -> ok | {error, term()}.
start() ->
    case application:ensure_all_started(?MODULE) of
        {ok, _} -> ok;
        {error, _} = Err -> Err
    end.

-spec stop() -> ok | {error, term()}.
stop() ->
    application:stop(?MODULE).

-spec get(uri() | [uri()]) -> {ok, http_reply()} | {error, error_reason()}.
get(URI) ->
    get(URI, #{}).

-spec get([uri()], req_opts()) -> [{ok, http_reply()} | {error, error_reason()}];
         (uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
get(URIs, Opts) when is_list(URIs) ->
    parallel_eval(get, URIs, [Opts]);
get({http, _UserInfo, Host, Port, Path, Query}, Opts) ->
    DeadLine = case maps:get(timeout, Opts, ?REQ_TIMEOUT) of
               {abs, AbsTime} -> AbsTime;
               Timeout -> current_time() + Timeout
           end,
    Families = maps:get(ip_family, Opts, [inet]),
    Hdrs = [{<<"host">>, unicode:characters_to_binary(Host)},
            {<<"connection">>, <<"close">>}|
            maps:get(headers, Opts, [])],
    req({get, Path, Query, Hdrs}, Host, Families, Port, DeadLine, 1).

-spec post([{uri(), iodata()}]) -> [{ok, http_reply()} | {error, error_reason()}];
          ({uri(), iodata()}) -> {ok, http_reply()} | {error, error_reason()}.
post(URIs) when is_list(URIs) ->
    post(URIs, #{});
post({URI, Body}) ->
    post(URI, Body, #{}).

-spec post(uri(), iodata()) -> {ok, http_reply()} | {error, error_reason()};
          ({uri(), iodata()}, req_opts()) -> {ok, http_reply()} | {error, error_reason()};
          ([{uri(), iodata()}], req_opts()) -> [{ok, http_reply()} | {error, error_reason()}].
post(URIs, Opts) when is_list(URIs) ->
    parallel_eval(post, URIs, [Opts]);
post({URI, Body}, Opts) ->
    post(URI, Body, Opts);
post(URI, Body) ->
    post(URI, Body, #{}).

-spec post(uri(), iodata(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
post({http, _UserInfo, Host, Port, Path, Query}, Body, Opts) ->
    DeadLine = case maps:get(timeout, Opts, ?REQ_TIMEOUT) of
               {abs, AbsTime} -> AbsTime;
               Timeout -> current_time() + Timeout
           end,
    Families = maps:get(ip_family, Opts, [inet]),
    ContentType = maps:get(content_type, Opts, ?DEFAULT_CONTENT_TYPE),
    Hdrs = [{<<"host">>, unicode:characters_to_binary(Host)},
            {<<"connection">>, <<"close">>},
            {<<"content-type">>, ContentType}|
            maps:get(headers, Opts, [])],
    req({post, Path, Query, Hdrs, Body}, Host, Families, Port, DeadLine, 1).

-spec format_error(error_reason()) -> string().
format_error({dns, Reason}) ->
    format("DNS lookup failed: ~s", [format_inet_error(Reason)]);
format_error({http, Reason}) ->
    format("HTTP request failed: ~s", [format_inet_error(Reason)]);
format_error({system_error, Reason}) ->
    format("Internal system error: ~p", [Reason]).

-spec proxy_status(http_reply() | error_reason()) -> non_neg_integer().
proxy_status({Status, _Headers, _Body}) -> Status;
proxy_status({system_error, _}) -> 500;
proxy_status({_, timeout}) -> 504;
proxy_status({_, etimedout}) -> 504;
proxy_status(_) -> 502.

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec req(req(), http_uri:host(), [inet | inet6, ...], inet:port_number(),
          millisecs(), pos_integer()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(Req, Host, Families, Port, DeadLine, Retries) ->
    case lookup(Host, Families, DeadLine) of
        {ok, Addrs} ->
            Ret = req(Req, Addrs, Port, DeadLine, {http, timeout}),
            retry_req(Req, Host, Families, Port, DeadLine, Retries, Ret);
        {error, _} = Ret ->
            retry_req(Req, Host, Families, Port, DeadLine, Retries, Ret)
    end.

-spec retry_req(req(), http_uri:host(), [inet | inet6, ...], inet:port_number(),
                millisecs(), pos_integer(), {ok, http_reply()} | {error, error_reason()}) ->
          {ok, http_reply()} | {error, error_reason()}.
retry_req(Req, Host, Families, Port, DeadLine, Retries, Ret) ->
    case need_retry(Ret) of
        true ->
            Timeout = Retries * ?RETRY_TIMEOUT,
            case (current_time() + Timeout) < DeadLine of
                true ->
                    timer:sleep(Timeout),
                    req(Req, Host, Families, Port, DeadLine, Retries+1);
                false ->
                    Ret
            end;
        false ->
            Ret
    end.

-spec req(req(), [addr_family()], inet:port_number(), millisecs(), error_reason()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(Req, [{Addr, Family}|Addrs], Port, DeadLine, Reason) ->
    case timeout(DeadLine) of
        Timeout when Timeout > 0 ->
            ?LOG_DEBUG("Performing GET to http://~s:~B", [format_addr(Addr), Port]),
            case gun:open(Addr, Port, #{transport => tcp,
                                        transport_opts => transport_opts(Family),
                                        retry => 0}) of
                {ok, ConnPid} ->
                    MRef = erlang:monitor(process, ConnPid),
                    Ret = receive
                              {gun_up, ConnPid, _Protocol} ->
                                  req(Req, ConnPid, MRef, DeadLine);
                              {'DOWN', MRef, process, ConnPid, Why} ->
                                  {error, prep_reason(Why)}
                          after Timeout ->
                                  gun:close(ConnPid),
                                  {error, {http, timeout}}
                          end,
                    erlang:demonitor(MRef),
                    gun:flush(ConnPid),
                    case Ret of
                        {ok, _} = OK ->
                            OK;
                        {error, NewReason} ->
                            req(Req, Addrs, Port, DeadLine, NewReason)
                    end;
                {error, Why} ->
                    req(Req, Addrs, Port, DeadLine, {system_error, Why})
            end;
        _ ->
            {error, Reason}
    end;
req(_, [], _, _, Reason) ->
    {error, Reason}.

-spec req(req(), pid(), reference(), millisecs()) ->
          {ok, http_reply()} | {error, {http, inet_error_reason()}}.
req(Req, ConnPid, MRef, DeadLine) ->
    Timeout = timeout(DeadLine),
    StreamRef = case Req of
                    {get, Path, Query, Hdrs} ->
                        gun:get(ConnPid, Path ++ Query, Hdrs);
                    {post, Path, Query, Hdrs, Body} ->
                        gun:post(ConnPid, Path ++ Query, Hdrs, Body)
                end,
    receive
        {gun_response, ConnPid, StreamRef, fin, Status, Headers} ->
            {ok, {Status, Headers, <<>>}};
        {gun_response, ConnPid, StreamRef, nofin, Status, Headers} ->
            recv_data(ConnPid, MRef, StreamRef, DeadLine, Status, Headers, <<>>);
        {'DOWN', MRef, process, ConnPid, Why} ->
            {error, prep_reason(Why)}
    after Timeout ->
            gun:close(ConnPid),
            {error, {http, timeout}}
    end.

-spec recv_data(pid(), reference(), reference(), millisecs(), non_neg_integer(), headers(), binary()) ->
          {ok, http_reply()} | {error, {http, inet_error_reason()}}.
recv_data(ConnPid, MRef, StreamRef, DeadLine, Status, Headers, Buf) ->
    Timeout = timeout(DeadLine),
    receive
        {gun_data, ConnPid, StreamRef, nofin, Data} ->
            recv_data(ConnPid, MRef, StreamRef, DeadLine, Status, Headers, <<Buf/binary, Data/binary>>);
        {gun_data, ConnPid, StreamRef, fin, Data} ->
            {ok, {Status, Headers, <<Buf/binary, Data/binary>>}};
        {'DOWN', MRef, process, ConnPid, Why} ->
            {error, prep_reason(Why)}
    after Timeout ->
            gun:close(ConnPid),
            {error, {http, timeout}}
    end.

-spec need_retry({ok, http_reply()} | {error, error_reason()}) -> boolean().
need_retry({ok, {Status, _, _}}) when Status < 500; Status >= 600 ->
    false;
need_retry(_) ->
    true.

%%%-------------------------------------------------------------------
%%% DNS lookup
%%%-------------------------------------------------------------------
-spec lookup(http_uri:host(), [inet | inet6, ...], millisecs()) ->
          {ok, [addr_family(), ...]} | {error, {dns, inet_error_reason()}}.
lookup(Host, Families, DeadLine) ->
    case inet:parse_address(Host) of
        {ok, IP} ->
            {ok, [{IP, get_addr_family(IP)}]};
        {error, _} ->
            Addrs = [{Host, Family} || Family <- lists:reverse(Families)],
            lookup(Addrs, DeadLine, [], nxdomain)
    end.

-spec lookup([host_family()], millisecs(), [addr_family()], inet_error_reason()) ->
          {ok, [addr_family(), ...]} | {error, {dns, inet_error_reason()}}.
lookup([{Host, Family}|Addrs], DeadLine, Res, Err) ->
    Timeout = min(?DNS_TIMEOUT, timeout(DeadLine)),
    ?LOG_DEBUG("Looking up ~s address for ~ts",
               [format_family(Family), Host]),
    case inet:gethostbyname(Host, Family, Timeout) of
        {ok, HostEntry} ->
            Addrs1 = host_entry_to_addrs(HostEntry),
            Addrs2 = [{Addr, Family} || Addr <- Addrs1],
            lookup(Addrs, DeadLine, Addrs2 ++ Res, Err);
        {error, Why} ->
            lookup(Addrs, DeadLine, Res, Why)
    end;
lookup([], _DeadLine, [], Err) ->
    {error, {dns, Err}};
lookup([], _DeadLine, Res, _Err) ->
    {ok, Res}.

-spec host_entry_to_addrs(inet:hostent()) -> [inet:ip_address()].
host_entry_to_addrs(#hostent{h_addr_list = AddrList}) ->
    lists:filter(
      fun(Addr) ->
              try get_addr_family(Addr) of
                  _ -> true
              catch _:badarg ->
                      false
              end
      end, AddrList).

-spec get_addr_family(inet:ip_address() | term()) -> inet | inet6.
get_addr_family({_, _, _, _}) -> inet;
get_addr_family({_, _, _, _, _, _, _, _}) -> inet6;
get_addr_family(_) -> erlang:error(badarg).

%%%-------------------------------------------------------------------
%%% Formatters
%%%-------------------------------------------------------------------
-spec format_inet_error(inet_error_reason()) -> string().
format_inet_error(closed) ->
    "connection closed unexpectedly";
format_inet_error(timeout) ->
    "request timed out";
format_inet_error(Reason) when is_atom(Reason) ->
    case inet:format_error(Reason) of
        "unknown POSIX error" -> atom_to_list(Reason);
        Txt -> Txt
    end;
format_inet_error(Reason) ->
    lists:flatten(io_lib:format("unexpected error: ~p", [Reason])).

-spec format_family(inet | inet6) -> string().
format_family(inet) -> "IPv4";
format_family(inet6) -> "IPv6".

-spec format_addr(inet:ip_address()) -> string().
format_addr({_, _, _, _} = IPv4) ->
    inet:ntoa(IPv4);
format_addr({_, _, _, _, _, _, _, _} = IPv6) ->
    "[" ++ inet:ntoa(IPv6) ++ "]".

-spec format(io:format(), list()) -> string().
format(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).

-spec prep_reason(term()) -> error_reason().
prep_reason({shutdown, Reason}) ->
    {http, Reason};
prep_reason(Reason) ->
    {system_error, Reason}.

%%%-------------------------------------------------------------------
%%% Aux
%%%-------------------------------------------------------------------
-spec current_time() -> millisecs().
current_time() ->
    erlang:system_time(millisecond).

-spec timeout(millisecs()) -> non_neg_integer().
timeout(DeadLine) ->
    max(0, DeadLine - current_time()).

transport_opts(Family) ->
    [{send_timeout, ?TCP_SEND_TIMEOUT},
     {send_timeout_close, true},
     Family].

parallel_eval(Fun, URIs, Args) ->
    Self = self(),
    Pids = lists:map(
             fun(URI) ->
                     spawn_monitor(
                       fun() ->
                               Self ! {self(), apply(?MODULE, Fun, [URI|Args])}
                       end)
             end, URIs),
    collect_responses(Pids, []).

collect_responses([], Acc) ->
    lists:reverse(Acc);
collect_responses([{Pid, MRef}|Pids], Acc) ->
    Response = receive
                   {Pid, Ret} ->
                       erlang:demonitor(MRef, [flush]),
                       Ret;
                   {'DOWN', MRef, process, Pid, Reason} ->
                       {error, {system_error, Reason}}
               end,
    collect_responses(Pids, [Response|Acc]).
