%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 29 Oct 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_httpd_test).

-behaviour(cowboy_rest).

%% API
-export([start/0]).
-export([stop/0]).
%% Cowboy REST callbacks
-export([init/2]).
-export([content_types_accepted/2]).
-export([content_types_provided/2]).
-export([allowed_methods/2]).
-export([handle_request/2]).
-export([delete_resource/2]).

-include_lib("kernel/include/logger.hrl").

-define(MIME_PLAIN, <<"text/plain">>).
-define(MIME_JSON, <<"application/json">>).
-define(MIME_PROBLEM_REPORT, <<"application/problem+json">>).

%%%===================================================================
%%% API
%%%===================================================================
start() ->
    case application:ensure_all_started(cowboy) of
        {ok, _} ->
            {ok, CurrentDirectory} = file:get_cwd(),
            CertPath = filename:join([CurrentDirectory, "test","cert.pem"]),
            KeyPath = filename:join([CurrentDirectory,"test","key.pem"]),

            Dispatch = cowboy_router:compile(
                         [{'_', [{"/[...]", ?MODULE, #{}}]}]),
            {ok, _} = cowboy:start_clear(?MODULE,
                               [{port, 0}, {ip, {127, 0, 0, 1}}],
                               #{env => #{dispatch => Dispatch},
                                 shutdown_timeout => timer:minutes(5)}),
            {ok, _} = cowboy:start_tls(https_listener,
                [
                    {port, 0},
                    {ip, {127, 0, 0, 1}},
                    {certfile, CertPath},
                    {keyfile, KeyPath}
                ],
                #{env => #{dispatch => Dispatch}}
            );
        Err ->
            Err
    end.

stop() ->
    cowboy:stop_listener(?MODULE),
    cowboy:stop_listener(https_listener),
    application:stop(cowboy).

init(Req, State) ->
    process_flag(trap_exit, true),
    {cowboy_rest, Req, State}.

content_types_accepted(Req, State) ->
    Result = [{{<<"application">>, <<"json">>, '*'}, handle_request}],
    {Result, Req, State}.

content_types_provided(Req, State) ->
    Result = [{{<<"application">>, <<"json">>, '*'}, handle_request},
              {{<<"application">>, <<"problem+json">>, '*'}, handle_request}],
    {Result, Req, State}.

allowed_methods(Req, State) ->
    {[<<"POST">>, <<"GET">>, <<"DELETE">>, <<"OPTIONS">>], Req, State}.

delete_resource(Req, State) ->
    handle_request(Req, State).

handle_request(#{method := Method, path_info := Info} = Req, State) ->
    handle(Method, Info, Req, State).

%%%===================================================================
%%% Internal functions
%%%===================================================================
handle(_, [<<"empty">>], Req, State) ->
    response(200, <<>>, ?MIME_PLAIN, Req, State);
handle(_, [<<"empty-json">>], Req, State) ->
    response(200, jiffy:encode(#{}), ?MIME_JSON, Req, State);
handle(<<"POST">>, [<<"echo">>], Req, State) ->
    {Data, Req1} = read_body(Req),
    response(200, Data, ?MIME_JSON, Req1, State);
handle(_, [<<"timeout">>], Req, State) ->
    timer:sleep(timer:minutes(1)),
    response(200, <<"delayed response">>, ?MIME_PLAIN, Req, State);
handle(_, [<<"timeout">>, Time], Req, State) ->
    Milli = binary_to_integer(Time),
    timer:sleep(Milli),
    response(200, <<"delayed response">>, ?MIME_PLAIN, Req, State);
handle(_, [<<"status">>, S], Req, State) ->
    Status = binary_to_integer(S),
    Problem = #{status => Status},
    response(Status, jiffy:encode(Problem), ?MIME_PROBLEM_REPORT, Req, State);
handle(_, [<<"fail">>], _, _) ->
    erlang:error(intentional_fail).

response(Status, Data, Type, Req, State) when is_binary(Data) ->
    Hdrs = #{<<"content-type">> => Type},
    Req1 = cowboy_req:reply(Status, Hdrs, Data, Req),
    {stop, Req1, State}.

read_body(Req) ->
    read_body(Req, <<>>).

read_body(Req, Buf) ->
    case cowboy_req:read_body(Req) of
        {more, Data, Req1} ->
            read_body(Req1, <<Buf/binary, Data/binary>>);
        {ok, Data, Req1} ->
            {<<Buf/binary, Data/binary>>, Req1}
    end.
