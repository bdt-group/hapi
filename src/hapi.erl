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
-export([delete/1, delete/2]).
-export([post/1, post/2, post/3]).
-export([format_error/1]).
-export([proxy_status/1]).

-include_lib("kernel/include/inet.hrl").
-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_CONTENT_TYPE, <<"application/json">>).
-define(DNS_TIMEOUT, timer:seconds(5)).
-define(TCP_SEND_TIMEOUT, timer:seconds(5)).
-define(REQ_TIMEOUT, timer:seconds(30)).
-define(MAX_RETRIES, infinity).
-define(RETRY_TIMEOUT, timer:seconds(1)).

-type uri() :: {http, http_uri:user_info(),
                http_uri:host(), inet:port_number(),
                http_uri:path(), http_uri:query()}.
-type req_opts() :: #{timeout => millisecs() | {abs, millisecs()},
                      timeout_per_request => timeout(),
                      max_retries => non_neg_integer() | infinity,
                      retry_base_timeout => millisecs(),
                      auth => auth(),
                      headers => headers(),
                      ip_family => [inet | inet6, ...]}.
-type retry_policy() :: {millisecs(), non_neg_integer(), non_neg_integer() | infinity}.
-type host_family() :: {http_uri:host(), inet | inet6}.
-type addr_family() :: {inet:ip_address(), inet | inet6}.
-type headers() :: [{binary(), binary()}].
-type method() :: get | post | delete.
-type req() :: {get | delete, http_uri:path(), http_uri:query(), headers()} |
               {post, http_uri:path(), http_uri:query(), headers(), iodata()}.
-type http_reply() :: {non_neg_integer(), headers(), binary()}.
-type millisecs() :: non_neg_integer().
-type auth() :: #{method := basic,
                  username := iodata(),
                  password := iodata()}.
-type inet_error_reason() :: timeout | closed | inet:posix() | term().
-type error_reason() :: {dns, inet_error_reason()} |
                        {http, inet_error_reason()} |
                        {system_error, term()}.

-export_type([uri/0, error_reason/0, http_reply/0, req_opts/0, method/0, headers/0]).

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
get(URI, Opts) ->
    req(get, URI, Opts).

-spec delete(uri() | [uri()]) -> {ok, http_reply()} | {error, error_reason()}.
delete(URI) ->
    delete(URI, #{}).

-spec delete([uri()], req_opts()) -> [{ok, http_reply()} | {error, error_reason()}];
            (uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
delete(URIs, Opts) when is_list(URIs) ->
    parallel_eval(delete, URIs, [Opts]);
delete(URI, Opts) ->
    req(delete, URI, Opts).

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
post(URI, Body, Opts) ->
    req({post, Body}, URI, Opts).

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
-spec req(get | delete | {post, iodata()}, uri(), req_opts()) ->
                 {ok, http_reply()} | {error, error_reason()}.
req(Method, {http, _UserInfo, Host, Port, Path, Query} = URI, Opts) ->
    DeadLine = case maps:get(timeout, Opts, ?REQ_TIMEOUT) of
                   {abs, AbsTime} -> AbsTime;
                   Timeout -> current_time() + Timeout
               end,
    ReqTimeout = maps:get(timeout_per_request, Opts, infinity),
    MaxRetries = maps:get(max_retries, Opts, ?MAX_RETRIES),
    RetryTimeout = maps:get(retry_base_timeout, Opts, ?RETRY_TIMEOUT),
    Families = maps:get(ip_family, Opts, [inet]),
    Hdrs = make_headers(URI, Opts),
    Req = case Method of
              {post, Body} -> {post, Path, Query, Hdrs, Body};
              _ -> {Method, Path, Query, Hdrs}
          end,
    req(Req, Host, Families, Port, DeadLine, ReqTimeout, {RetryTimeout, 0, MaxRetries}).

-spec req(req(), http_uri:host(), [inet | inet6, ...], inet:port_number(),
          millisecs(), timeout(), retry_policy()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(Req, Host, Families, Port, DeadLine, ReqTimeout, Retries) ->
    case lookup(Host, Families, DeadLine) of
        {ok, Addrs} ->
            Ret = req(Req, Addrs, Port, DeadLine, ReqTimeout, {http, timeout}),
            retry_req(Req, Host, Families, Port, DeadLine, ReqTimeout, Retries, Ret);
        {error, _} = Ret ->
            retry_req(Req, Host, Families, Port, DeadLine, ReqTimeout, Retries, Ret)
    end.

-spec retry_req(req(), http_uri:host(), [inet | inet6, ...], inet:port_number(),
                millisecs(), timeout(), retry_policy(),
                {ok, http_reply()} | {error, error_reason()}) ->
          {ok, http_reply()} | {error, error_reason()}.
retry_req(_Req, _Host, _Families, _Port, _DeadLine, _ReqTimeout,
          {_RetryTimeout, MaxRetries, MaxRetries}, Ret) ->
    Ret;
retry_req(Req, Host, Families, Port, DeadLine, ReqTimeout,
          {RetryTimeout, Retry, MaxRetries}, Ret) ->
    case need_retry(Ret) of
        true ->
            Timeout = Retry * RetryTimeout,
            case (current_time() + Timeout) < DeadLine of
                true ->
                    timer:sleep(Timeout),
                    req(Req, Host, Families, Port, DeadLine, ReqTimeout,
                        {RetryTimeout, Retry+1, MaxRetries});
                false ->
                    Ret
            end;
        false ->
            Ret
    end.

-spec req(req(), [addr_family()], inet:port_number(), millisecs(), timeout(), error_reason()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(Req, [{Addr, Family}|Addrs], Port, DeadLine, ReqTimeout, Reason) ->
    ReqDeadLine = deadline_per_request(DeadLine, ReqTimeout, length(Addrs) + 1),
    case timeout(ReqDeadLine) of
        Timeout when Timeout > 0 ->
            ?LOG_DEBUG("Performing ~s to http://~s:~B (timeout: ~.3fs)~n",
                       [format_method(Req), format_addr(Addr), Port, Timeout/1000]),
            case gun:open(Addr, Port, #{transport => tcp,
                                        transport_opts => transport_opts(Family),
                                        retry => 0}) of
                {ok, ConnPid} ->
                    MRef = erlang:monitor(process, ConnPid),
                    Ret = receive
                              {gun_up, ConnPid, _Protocol} ->
                                  req(Req, ConnPid, MRef, ReqDeadLine);
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
                            req(Req, Addrs, Port, DeadLine, ReqTimeout, NewReason)
                    end;
                {error, Why} ->
                    req(Req, Addrs, Port, DeadLine, ReqTimeout, {system_error, Why})
            end;
        _ ->
            {error, Reason}
    end;
req(_, [], _, _, _, Reason) ->
    {error, Reason}.

-spec req(req(), pid(), reference(), millisecs()) ->
          {ok, http_reply()} | {error, {http, inet_error_reason()}}.
req(Req, ConnPid, MRef, DeadLine) ->
    Timeout = timeout(DeadLine),
    StreamRef = case Req of
                    {get, Path, Query, Hdrs} ->
                        gun:get(ConnPid, Path ++ Query, Hdrs);
                    {post, Path, Query, Hdrs, Body} ->
                        gun:post(ConnPid, Path ++ Query, Hdrs, Body);
                    {delete, Path, Query, Hdrs} ->
                        gun:delete(ConnPid, Path ++ Query, Hdrs)
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

-spec make_headers(uri(), hapi:req_opts()) -> headers().
make_headers({_Scheme, _UserInfo, Host, _Port, _Path, _Query}, ReqOpts) ->
    Hdrs1 = maps:get(headers, ReqOpts, []),
    Hdrs2 = case maps:find(auth, ReqOpts) of
                {ok, #{type := basic,
                       username := User,
                       password := Pass}} ->
                    Authz = base64:encode(iolist_to_binary([User, $:, Pass])),
                    [{<<"authorization">>, <<"Basic ", Authz/binary>>}|Hdrs1];
                error ->
                    Hdrs1
            end,
    [{<<"host">>, unicode:characters_to_binary(Host)},
     {<<"connection">>, <<"close">>}|
     Hdrs2].

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

-spec format_method(req()) -> string().
format_method(Req) ->
    string:uppercase(atom_to_list(element(1, Req))).

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

-spec deadline_per_request(millisecs(), timeout(), pos_integer()) -> millisecs().
deadline_per_request(DeadLine, ReqTimeout, N) ->
    CurrTime = current_time(),
    Timeout = max(0, DeadLine - CurrTime),
    CurrTime +
        case is_integer(ReqTimeout) of
            true -> min(Timeout, ReqTimeout);
            false -> Timeout div N
        end.

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
