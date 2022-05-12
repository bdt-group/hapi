%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% @doc
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

-type scheme() :: http | https.
-type transport() :: tcp | tls.
-type uri() :: {http, http_uri:user_info(),
                http_uri:host(), inet:port_number(),
                http_uri:path(), http_uri:query()} |
               uri_string:uri_map().
-type req_opts() :: #{timeout => hapi_misc:millisecs() |
                                 {abs, hapi_misc:millisecs()},
                      timeout_per_request => timeout(),
                      max_retries => non_neg_integer() | infinity,
                      retry_base_timeout => hapi_misc:millisecs(),
                      auth => auth(),
                      headers => headers(),
                      use_pool => boolean(),
                      ip_family => [inet | inet6, ...]}.
-type retry_policy() :: {hapi_misc:millisecs(), non_neg_integer(), non_neg_integer() | infinity}.
-type host_family() :: {http_uri:host(), inet | inet6}.
-type addr_family() :: {inet:ip_address(), inet | inet6}.
-type endpoint() :: {inet:ip_address(), inet:port_number()}.
-type headers() :: [{binary(), binary()}].
-type method() :: get | post | delete.
-type req() :: {get | delete, schema(), http_uri:path(), http_uri:query(), headers()} |
               {post, scheme(), http_uri:path(), http_uri:query(), headers(), iodata()}.
-type http_reply() :: {non_neg_integer(), headers(), binary()}.
-type auth() :: #{type := basic,
                  username := iodata(),
                  password := iodata()}.
-type inet_error_reason() :: timeout | closed | overloaded | inet:posix() | term().
-type error_reason() :: {dns, inet_error_reason()} |
                        {http, inet_error_reason()} |
                        {system_error, term()} |
                        {exit, term()}.

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

-spec get(uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
get(URI, Opts) ->
    req(get, URI, Opts).

-spec delete(uri() | [uri()]) -> {ok, http_reply()} | {error, error_reason()}.
delete(URI) ->
    delete(URI, #{}).

-spec delete(uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
delete(URI, Opts) ->
    req(delete, URI, Opts).

-spec post({uri(), iodata()}) -> {ok, http_reply()} | {error, error_reason()}.
post({URI, Body}) ->
    post(URI, Body, #{}).

-spec post(uri(), iodata()) -> {ok, http_reply()} | {error, error_reason()};
          ({uri(), iodata()}, req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
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
    format("Internal system error: ~p", [Reason]);
format_error({exit, Reason}) ->
    format("HTTP request interrupted with reason: ~p", [Reason]).

-spec proxy_status(http_reply() | error_reason()) -> non_neg_integer().
proxy_status({Status, _Headers, _Body}) -> Status;
proxy_status({system_error, _}) -> 500;
proxy_status({exit, _}) -> 503;
proxy_status({_, timeout}) -> 504;
proxy_status({_, etimedout}) -> 504;
proxy_status({_, overloaded}) -> 429;
proxy_status(_) -> 502.

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec req(get | delete | {post, iodata()}, uri(), req_opts()) ->
                 {ok, http_reply()} | {error, error_reason()}.
req(Method, URI0, Opts) when is_map(URI0), map_size(URI0) > 0 ->
    URI = format_uri_map(URI0),
    Host = maps:get(host, URI),
    Port = maps:get(port, URI, 80),
    Path = maps:get(path, URI, ""),
    Scheme = maps:get(scheme, URI),
    Query = maps:get(query, URI, ""),
    UserInfo = maps:get(userinfo, URI, ""),
    req(Method, {Scheme, UserInfo, Host, Port, Path, Query}, Opts);

req(Method, {Scheme, _UserInfo, Host, Port, Path, Query} = URI, Opts) ->
    DeadLine = case maps:get(timeout, Opts, ?REQ_TIMEOUT) of
                   {abs, AbsTime} -> AbsTime;
                   Timeout -> hapi_misc:current_time() + Timeout
               end,
    ReqTimeout = maps:get(timeout_per_request, Opts, infinity),
    MaxRetries = maps:get(max_retries, Opts, ?MAX_RETRIES),
    RetryTimeout = maps:get(retry_base_timeout, Opts, ?RETRY_TIMEOUT),
    Families = maps:get(ip_family, Opts, [inet]),
    Hdrs = make_headers(URI, Opts),
    Req = case Method of
              {post, Body} -> {post, Scheme, Path, Query, Hdrs, Body};
              _ -> {Method, Scheme, Path, Query, Hdrs}
          end,
    req(Req, Host, Families, Port, DeadLine, ReqTimeout, {RetryTimeout, 0, MaxRetries}).

-spec req(req(), http_uri:host(), [inet | inet6, ...], inet:port_number(),
          hapi_misc:millisecs(), timeout(), retry_policy()) ->
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
                hapi_misc:millisecs(), timeout(), retry_policy(),
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
            case (hapi_misc:current_time() + Timeout) < DeadLine of
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

-spec req(req(), [addr_family()], inet:port_number(), hapi_misc:millisecs(), timeout(), error_reason()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(Req, [{Addr, Family}|Addrs], Port, DeadLine, ReqTimeout, Reason) ->
    ReqDeadLine = deadline_per_request(DeadLine, ReqTimeout, length(Addrs) + 1),
    case hapi_misc:timeout(ReqDeadLine) of
        Timeout when Timeout > 0 ->
            Scheme = extract_scheme(Req),
            Transport = infer_transport(Scheme),
            ?LOG_DEBUG("Performing ~s to ~p://~s:~B (timeout: ~.3fs)",
                       [format_method(Req), Scheme, hapi_misc:format_addr(Addr), Port, Timeout/1000]),
            case open({Addr, Port}, #{transport => Transport,
                                      transport_opts => transport_opts(Family),
                                      retry => 0}, Req, ReqDeadLine) of
                {ok, ConnPid} ->
                    MRef = erlang:monitor(process, ConnPid),
                    Ret = receive
                              {gun_up, ConnPid, _Protocol} ->
                                  req({Addr, Port}, Req, ConnPid, MRef, ReqDeadLine);
                              {'DOWN', MRef, process, ConnPid, Why} ->
                                  {error, prep_reason(Why)};
                              {'EXIT', _, Why} ->
                                  close({Addr, Port}, ConnPid, undefined, Req),
                                  {error, {exit, Why}}
                          after Timeout ->
                                  close({Addr, Port}, ConnPid, undefined, Req),
                                  {error, {http, timeout}}
                          end,
                    erlang:demonitor(MRef),
                    gun:flush(ConnPid),
                    case Ret of
                        {ok, _} = OK ->
                            OK;
                        {error, {exit, _}} ->
                            Ret;
                        {error, NewReason} ->
                            req(Req, Addrs, Port, DeadLine, ReqTimeout, NewReason)
                    end;
                {error, Why} ->
                    req(Req, Addrs, Port, DeadLine, ReqTimeout, prep_reason(Why))
            end;
        _ ->
            {error, Reason}
    end;
req(_, [], _, _, _, Reason) ->
    {error, Reason}.

-spec req(endpoint(), req(), pid(), reference(), hapi_misc:millisecs()) ->
          {ok, http_reply()} | {error, error_reason()}.
req(AddrPort, Req, ConnPid, MRef, DeadLine) ->
    Timeout = hapi_misc:timeout(DeadLine),
    ReqOpts = #{reply_to => self()},
    StreamRef = case Req of
                    {get, _, Path, Query, Hdrs} ->
                        gun:get(ConnPid, Path ++ Query, Hdrs, ReqOpts);
                    {post, _, Path, Query, Hdrs, Body} ->
                        gun:post(ConnPid, Path ++ Query, Hdrs, Body, ReqOpts);
                    {delete, _, Path, Query, Hdrs} ->
                        gun:delete(ConnPid, Path ++ Query, Hdrs, ReqOpts)
                end,
    receive
        {gun_response, ConnPid, StreamRef, fin, Status, Headers} ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {ok, {Status, Headers, <<>>}};
        {gun_response, ConnPid, StreamRef, nofin, Status, Headers} ->
            recv_data(AddrPort, Req, ConnPid, MRef, StreamRef, DeadLine, Status, Headers, <<>>);
        {'DOWN', MRef, process, ConnPid, Why} ->
            {error, prep_reason(Why)};
        {'EXIT', _, Why} ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {error, {exit, Why}}
    after Timeout ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {error, {http, timeout}}
    end.

-spec recv_data(endpoint(), req(), pid(), reference(), reference(),
                hapi_misc:millisecs(), non_neg_integer(), headers(), binary()) ->
          {ok, http_reply()} | {error, error_reason()}.
recv_data(AddrPort, Req, ConnPid, MRef, StreamRef, DeadLine, Status, Headers, Buf) ->
    Timeout = hapi_misc:timeout(DeadLine),
    receive
        {gun_data, ConnPid, StreamRef, nofin, Data} ->
            recv_data(AddrPort, Req, ConnPid, MRef, StreamRef, DeadLine,
                      Status, Headers, <<Buf/binary, Data/binary>>);
        {gun_data, ConnPid, StreamRef, fin, Data} ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {ok, {Status, Headers, <<Buf/binary, Data/binary>>}};
        {'DOWN', MRef, process, ConnPid, Why} ->
            {error, prep_reason(Why)};
        {'EXIT', _, Why} ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {error, {exit, Why}}
    after Timeout ->
            close(AddrPort, ConnPid, StreamRef, Req),
            {error, {http, timeout}}
    end.

open({Addr, Port} = AddrPort, Opts, Req, DeadLine) ->
    case use_pool(Req) of
        true -> hapi_pool:open(AddrPort, Opts, DeadLine);
        false -> gun:open(Addr, Port, Opts)
    end.

close(AddrPort, ConnPid, StreamRef, Req) ->
    case use_pool(Req) of
        true -> hapi_pool:close(AddrPort, ConnPid, StreamRef);
        false -> gun:close(ConnPid)
    end.

-spec need_retry({ok, http_reply()} | {error, error_reason()}) -> boolean().
need_retry({ok, {Status, _, _}})
  when Status == 500; Status == 502; Status == 503; Status == 504; Status == 507 ->
    true;
need_retry({ok, _}) ->
    false;
need_retry({error, {exit, _}}) ->
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
    Hdrs3 = case maps:get(use_pool, ReqOpts, false) of
                true -> [{<<"connection">>, <<"keep-alive">>}|Hdrs2];
                false -> [{<<"connection">>, <<"close">>}|Hdrs2]
            end,
    [{<<"host">>, unicode:characters_to_binary(Host)} | Hdrs3].

use_pool(Req) ->
    Hdrs = element(4, Req),
    case lists:keyfind(<<"connection">>, 1, Hdrs) of
        {_, <<"keep-alive">>} -> true;
        _ -> false
    end.

%%%-------------------------------------------------------------------
%%% DNS lookup
%%%-------------------------------------------------------------------
-spec lookup(http_uri:host(), [inet | inet6, ...], hapi_misc:millisecs()) ->
          {ok, [addr_family(), ...]} | {error, {dns, inet_error_reason()}}.
lookup(Host, Families, DeadLine) ->
    case inet:parse_address(Host) of
        {ok, IP} ->
            {ok, [{IP, get_addr_family(IP)}]};
        {error, _} ->
            Addrs = [{Host, Family} || Family <- lists:reverse(Families)],
            lookup(Addrs, DeadLine, [], nxdomain)
    end.

-spec lookup([host_family()], hapi_misc:millisecs(), [addr_family()], inet_error_reason()) ->
          {ok, [addr_family(), ...]} | {error, {dns, inet_error_reason()}}.
lookup([{Host, Family}|Addrs], DeadLine, Res, Err) ->
    Timeout = min(?DNS_TIMEOUT, hapi_misc:timeout(DeadLine)),
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
-spec format_uri_map(uri_string:uri_map()) -> uri_string:uri_map().
format_uri_map(URIMap) ->
    maps:map(fun(_, V) when is_binary(V) -> binary_to_list(V);
                (_, V) -> V
             end, URIMap).

-spec format_inet_error(inet_error_reason()) -> string().
format_inet_error(closed) ->
    "connection closed unexpectedly";
format_inet_error(timeout) ->
    "request timed out";
format_inet_error(overloaded) ->
    "too many requests";
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

-spec format_method(req()) -> string().
format_method(Req) ->
    string:uppercase(atom_to_list(element(1, Req))).

-spec format(io:format(), list()) -> string().
format(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).

-spec prep_reason(term()) -> error_reason().
prep_reason({shutdown, Reason}) ->
    {http, Reason};
prep_reason(noproc) ->
    {http, closed};
prep_reason(Reason) when Reason == timeout;
                         Reason == closed;
                         Reason == overloaded ->
    {http, Reason};
prep_reason(Reason) ->
    {system_error, Reason}.

%%%-------------------------------------------------------------------
%%% Aux
%%%-------------------------------------------------------------------
-spec deadline_per_request(hapi_misc:millisecs(), timeout(), pos_integer()) ->
                                  hapi_misc:millisecs().
deadline_per_request(DeadLine, ReqTimeout, N) ->
    CurrTime = hapi_misc:current_time(),
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


-spec extract_scheme(req()) -> scheme().
extract_scheme(Req) -> element(2, Req).

-spec infer_transport(scheme()) -> transport().
infer_transport(http) -> tcp;
infer_transport(https) -> tls.