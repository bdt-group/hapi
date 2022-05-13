%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 29 Oct 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_eunit).

-compile(export_all).
-compile({no_auto_import, [get/0, get/1]}).
-compile(nowarn_export_all).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% API
%%%===================================================================
start_test() ->
    ?assertEqual(ok, load_config("default.yml")),
    ?assertEqual(ok, log:start()),
    ?assertEqual(ok, hapi:start()),
    ?assertMatch({ok, _}, hapi_httpd_test:start()).

get_test() ->
    URI = make_uri("/empty"),
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, hapi:get(URI)),
    assert_mailbox().

get_https_test() ->

    ssl:start(),
    {ok, _} = ssl:connect("127.0.0.1", get_https_port(),  [{verify, verify_none}], infinity),

    URI = #{scheme => "https", port => get_https_port(), host => "127.0.0.1", path => "/empty"},
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, hapi:get(URI)),
    assert_mailbox().

get_uri_string_test() ->
    Host = "127.0.0.1", Port = get_port(), Path = "/empty",
    URL = "http://" ++ Host ++ ":" ++ integer_to_list(Port) ++ Path,
    URI = uri_string:parse(URL),
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, hapi:get(URI)),
    assert_mailbox().

dns_lookup_test() ->
    URI = make_uri("localhost", "/empty"),
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, hapi:get(URI, opts())),
    assert_mailbox().

json_test() ->
    URI = make_uri("/empty-json"),
    ?assertMatch({ok, []},
                 hapi_json:get(URI, yval:options(#{}))),
    assert_mailbox().

auth_test() ->
    URI = make_uri("/empty"),
    Auth = #{type => basic,
             username => <<"user">>,
             password => ["pass"|<<"word">>]},
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, hapi:get(URI, opts(#{auth => Auth}))),
    assert_mailbox().

post_test() ->
    URI = make_uri("/empty-json"),
    ?assertMatch({ok, []},
                 hapi_json:post(URI, #{}, yval:options(#{}))),
    assert_mailbox().

delete_test() ->
    URI = make_uri("/empty-json"),
    ?assertMatch({ok, []},
                 hapi_json:delete(URI, yval:options(#{}))),
    assert_mailbox().

delete_no_content_test() ->
    URI = make_uri("/status/204"),
    ?assertMatch({ok, no_content},
                 hapi_json:delete(URI, yval:options(#{}))),
    assert_mailbox().

empty_json_test() ->
    URI = make_uri("/empty"),
    Ret = hapi_json:get(URI, yval:options(#{}), opts()),
    ?assertMatch({error, {malformed_json, <<>>}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(400, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

malformed_json_test() ->
    URI = make_uri("/echo"),
    Ret = hapi_json:post(URI, <<"{">>, yval:any()),
    ?assertMatch({error, {malformed_json, _}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(400, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

malformed_json_truncate_test() ->
    Data = lists:duplicate(2000, ${),
    URI = make_uri("/echo"),
    Ret = hapi_json:post(URI, list_to_binary(Data), yval:any()),
    ?assertMatch({error, {malformed_json, _}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(400, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

invalid_json_test() ->
    URI = make_uri("/empty-json"),
    Ret = hapi_json:delete(URI, yval:int(), opts()),
    ?assertMatch({error, {invalid_json, _, _}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(400, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

problem_report_test() ->
    URI = make_uri("/status/400"),
    Ret = hapi_json:get(URI, yval:options(#{})),
    ?assertMatch({error, {problem_report, #{status := 400}}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(400, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

request_failure_test() ->
    URI = make_uri("/fail"),
    Ret = hapi_json:get(URI, yval:options(#{}), opts()),
    ?assertMatch({error, {status, {500, _, _}}}, Ret),
    hapi_json:format_error(element(2, Ret)),
    ?assertEqual(500, hapi_json:proxy_status(element(2, Ret))),
    assert_mailbox().

dns_error_test() ->
    URI = make_uri("non-existent", "/dns-non-existent"),
    Ret = hapi:get(URI, opts()),
    ?assertMatch({error, {dns, _}}, Ret),
    hapi:format_error(element(2, Ret)),
    ?assertEqual(502, hapi:proxy_status(element(2, Ret))),
    assert_mailbox().

dns_timeout_test() ->
    URI = make_uri("/dns-timeout"),
    Ret = hapi:get(URI, opts(#{timeout => 1})),
    ?assertMatch({error, {_, timeout}}, Ret),
    hapi:format_error(element(2, Ret)),
    ?assertEqual(504, hapi:proxy_status(element(2, Ret))),
    assert_mailbox().

connect_timeout_test() ->
    {ok, Sock} = gen_tcp:listen(0, [inet]),
    {ok, {_, Port}} = inet:sockname(Sock),
    URI = make_uri("127.0.0.1", Port, "/connect-timeout"),
    Ret = hapi:get(URI, opts(#{timeout => {abs, 0}})),
    gen_tcp:close(Sock),
    ?assertEqual({error, {http, timeout}}, Ret),
    hapi:format_error(element(2, Ret)),
    ?assertEqual(504, hapi:proxy_status(element(2, Ret))),
    assert_mailbox().

connection_refused_test() ->
    URI = make_uri("127.0.0.1", 1, "/connection-refused"),
    Ret = hapi:get(URI, opts()),
    ?assertEqual({error, {http, econnrefused}}, Ret),
    hapi:format_error(element(2, Ret)),
    ?assertEqual(502, hapi:proxy_status(element(2, Ret))),
    assert_mailbox().

request_timeout_test() ->
    URI = make_uri("/timeout/2000"),
    ?assertEqual({error, {http, timeout}},
                 hapi:get(URI, opts(#{timeout => 1000}))),
    timer:sleep(2000),
    assert_mailbox().

exit_signal_test() ->
    process_flag(trap_exit, true),
    URI = make_uri("/timeout"),
    self() ! {'EXIT', self(), shutdown},
    Ret = hapi:get(URI, opts()),
    ?assertMatch({error, {exit, _}}, Ret),
    hapi:format_error(element(2, Ret)),
    ?assertEqual(503, hapi:proxy_status(element(2, Ret))),
    process_flag(trap_exit, false),
    assert_mailbox().

%%%===================================================================
%%% Pool tests
%%%===================================================================
pool_get_test() ->
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, get(pool_opts())),
    assert_mailbox(),
    check_pool_consistency(1).

pool_json_test() ->
    stop_pool(),
    URI = make_uri("/empty-json"),
    ?assertMatch({ok, []},
                 hapi_json:get(URI, yval:options(#{}), pool_opts())),
    assert_mailbox(),
    check_pool_consistency(1).

concurrent_get_test() ->
    stop_pool(),
    Self = self(),
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Self ! {self(), get(pool_opts())}
                       end)
             end, lists:seq(1, 10)),
    collect_responses(
      Refs,
      fun(Ret) -> ?assertMatch({ok, {200, _Hdrs, <<>>}}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(10).

concurrent_pool_full_test() ->
    stop_pool(),
    Self = self(),
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Self ! {self(), get(pool_opts())}
                       end)
             end, lists:seq(1, 20)),
    collect_responses(
      Refs,
      fun(Ret) -> ?assertMatch({ok, {200, _Hdrs, <<>>}}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(10).

single_caller_multiple_open_test() ->
    stop_pool(),
    AddrPort = get_addr_port(),
    Conns = lists:map(
              fun(_) ->
                      Ret = hapi_pool:open(AddrPort, #{}, deadline(5)),
                      ?assertMatch({ok, _}, Ret),
                      receive {gun_up, _, _} -> ok end,
                      Ret
              end, lists:seq(1, 5)),
    lists:foreach(
      fun({ok, ConnPid}) ->
              ?assertEqual(ok, hapi_pool:close(AddrPort, ConnPid, undefined))
      end, Conns),
    check_pool_consistency(5).

connection_down_test() ->
    stop_pool(),
    AddrPort = get_addr_port(),
    {ok, ConnPid} = hapi_pool:open(AddrPort, #{}, deadline(5)),
    receive {gun_up, _, _} -> ok end,
    exit(ConnPid, kill),
    timer:sleep(timer:seconds(1)),
    assert_mailbox(),
    check_pool_consistency(0).

caller_down_test() ->
    stop_pool(),
    Self = self(),
    Ref = spawn_monitor(
            fun() ->
                    AddrPort = get_addr_port(),
                    Ret = hapi_pool:open(AddrPort, #{}, deadline(5)),
                    receive {gun_up, _, _} -> ok end,
                    Self ! {self(), Ret}
            end),
    collect_responses(
      [Ref],
      fun(Ret) -> ?assertMatch({ok, _}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(1).

pool_request_timeout_test() ->
    stop_pool(),
    URI = make_uri("/timeout/2000"),
    ?assertEqual({error, {http, timeout}},
                 hapi:get(URI, pool_opts(#{timeout => 1000}))),
    timer:sleep(2000),
    assert_mailbox(),
    check_pool_consistency(1).

timeout_no_request_test() ->
    stop_pool(),
    Self = self(),
    ?assertEqual(ok, reload_config("min-pool.yml")),
    AddrPort = get_addr_port(),
    {ok, _ConnPid} = hapi_pool:open(AddrPort, #{}, deadline(2)),
    receive {gun_up, _, _} -> ok end,
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Ret = hapi_pool:open(AddrPort, #{}, deadline(1)),
                               timer:sleep(timer:seconds(3)),
                               Self ! {self(), Ret}
                       end)
             end, lists:seq(1, 10)),
    collect_responses(
      Refs,
      fun(Ret) -> ?assertEqual({error, timeout}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(1).

decrease_pool_test() ->
    stop_pool(),
    Self = self(),
    ?assertEqual(ok, reload_config("default.yml")),
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Self ! {self(), get(pool_opts())}
                       end)
             end, lists:seq(1, 10)),
    collect_responses(
      Refs,
      fun(Ret) -> ?assertMatch({ok, {200, _Hdrs, <<>>}}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(10),
    ?assertEqual(ok, reload_config("min-pool.yml")),
    lists:foreach(
      fun(_) ->
              ?assertMatch({ok, {200, _Hdrs, <<>>}}, get(pool_opts()))
      end, lists:seq(1, 5)),
    assert_mailbox(),
    check_pool_consistency(5),
    lists:foreach(
      fun(_) ->
              ?assertMatch({ok, {200, _Hdrs, <<>>}}, get(pool_opts()))
      end, lists:seq(1, 4)),
    assert_mailbox(),
    check_pool_consistency(1).

increase_pool_test() ->
    Self = self(),
    ?assertMatch({ok, {200, _Hdrs, <<>>}}, get(pool_opts())),
    assert_mailbox(),
    check_pool_consistency(1),
    ?assertEqual(ok, reload_config("default.yml")),
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Self ! {self(), get(pool_opts())}
                       end)
             end, lists:seq(1, 20)),
    collect_responses(
      Refs,
      fun(Ret) -> ?assertMatch({ok, {200, _Hdrs, <<>>}}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(10).

overload_test() ->
    stop_pool(),
    Self = self(),
    ?assertEqual(ok, reload_config("min-pool.yml")),
    AddrPort = get_addr_port(),
    {ok, ConnPid} = hapi_pool:open(AddrPort, #{}, deadline(5)),
    receive {gun_up, _, _} -> ok end,
    URI = make_uri("/timeout"),
    Opts = pool_opts(#{timeout => 3000, max_retries => 0}),
    Refs = lists:map(
             fun(_) ->
                     spawn_monitor(
                       fun() ->
                               Ret = hapi:get(URI, Opts),
                               Self ! {self(), Ret}
                       end)
             end, lists:seq(1, 10)),
    timer:sleep(timer:seconds(1)),
    %% This one will trigger {http, overloaded} responses for the queued 10 requests
    Ref = spawn_monitor(
            fun() ->
                    Self ! {self(), get(pool_opts())}
            end),
    collect_responses(
      Refs,
      fun(Ret) ->
              ?assertMatch({error, {http, overloaded}}, Ret),
              hapi:format_error(element(2, Ret)),
              ?assertEqual(429, hapi:proxy_status(element(2, Ret)))
      end),
    ?assertMatch(ok, hapi_pool:close(AddrPort, ConnPid, undefined)),
    collect_responses(
      [Ref],
      fun(Ret) -> ?assertMatch({ok, {200, _Hdrs, <<>>}}, Ret) end),
    assert_mailbox(),
    check_pool_consistency(1).

stop_test() ->
    stop_pool(),
    ?assertEqual(ok, hapi:stop()).

%%%===================================================================
%%% Internal functions
%%%===================================================================
get(Opts) ->
    get("/empty", Opts).

get(Path, Opts) ->
    URI = make_uri(Path),
    hapi:get(URI, Opts).

get_port() ->
    ranch:get_port(hapi_httpd_test).

get_https_port()->
    ranch:get_port(https_listener).

make_uri(Path) ->
    make_uri("127.0.0.1", Path).

make_uri(Host, Path) ->
    make_uri(Host, get_port(), Path).

make_uri(Host, Port, Path) ->
    make_uri("http", Host, Port, Path).

make_uri(Scheme, Host, Port, Path) ->
    URL = Scheme ++ "://" ++ Host ++ ":" ++ integer_to_list(Port) ++ Path,
    {ok, URI} = http_uri:parse(URL),
    URI.

get_addr_port() ->
    {{127, 0, 0, 1}, get_port()}.

pool_opts() ->
    maps:merge(opts(), #{use_pool => true}).

pool_opts(Opts) ->
    maps:merge(pool_opts(), Opts).

opts() ->
    #{timeout => 5000}.

opts(Opts) ->
    maps:merge(opts(), Opts).

load_config(Name) ->
    conf:load_file(filename:join("test", Name)).

reload_config(Name) ->
    conf:reload_file(filename:join("test", Name)).

collect_responses([{Pid, MRef}|Refs], CheckResponse) ->
    receive
        {Pid, Response} ->
            CheckResponse(Response),
            receive {'DOWN', MRef, process, Pid, _} -> ok end,
            collect_responses(Refs, CheckResponse);
        {'DOWN', MRef, process, Pid, _} = Msg ->
            erlang:error({unexpected_message, Msg})
    end;
collect_responses([], _) ->
    ok.

deadline(Secs) ->
    os:system_time(millisecond) + timer:seconds(Secs).

stop_pool() ->
    hapi_pool:stop(get_addr_port()).

check_pool_consistency(N) ->
    Pool = hapi_pool:get_state(get_addr_port()),
    ?assertEqual(N, length(maps:get(idle, Pool))),
    ?assertEqual(N, maps:size(maps:get(connections, Pool))),
    ?assertEqual(0, maps:size(maps:get(busy, Pool))),
    ?assertEqual(0, maps:size(maps:get(callers, Pool))),
    ?assertEqual(0, queue:len(maps:get(rq, Pool))),
    ?assertEqual(0, maps:get(rq_size, Pool)).

assert_mailbox() ->
    receive
        {gun_error, _, _, _} ->
            %% We cannot completely get rid of this message
            assert_mailbox();
        M ->
            erlang:error({unexpected_message, M})
    after 0 ->
            ok
    end.

%% dump_pool(TestName) ->
%%     ?debugFmt("State at ~s:~n~p", [TestName, hapi_pool:get_state(get_addr_port())]).
