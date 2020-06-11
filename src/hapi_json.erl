%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 18 Apr 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_json).

%% API
-export([get/2, get/3]).
-export([delete/2, delete/3]).
-export([post/3, post/4]).
-export([decode/2]).
-export([encode/1]).
-export([format_error/1]).
-export([proxy_status/1]).
-export_type([error_reason/0]).
-export_type([json_error_reason/0]).
-export_type([problem_report/0]).

-type problem_report() :: #{status := non_neg_integer(),
                            type => binary(),
                            title => binary(),
                            detail => binary(),
                            _ => term()}.
-type json_error_reason() :: {invalid_json, yval:error_reason(), yval:ctx()} |
                             {malformed_json, binary()}.
-type error_reason() :: {problem_report, problem_report()} |
                        {status, hapi:http_reply()} |
                        json_error_reason() |
                        hapi:error_reason().

%%%===================================================================
%%% API
%%%===================================================================
-spec get(hapi:uri(), yval:validator(T)) ->
                 {ok, T | no_content} | {error, error_reason()}.
get(URI, Validator) ->
    get(URI, Validator, #{}).

-spec get(hapi:uri(), yval:validator(T), hapi:req_opts()) ->
                 {ok, T | no_content} | {error, error_reason()}.
get(URI, Validator, Opts) ->
    Ret = hapi:get(URI, set_headers(get, Opts)),
    process_response(Ret, Validator).

-spec delete(hapi:uri(), yval:validator(T)) ->
                 {ok, T | no_content} | {error, error_reason()}.
delete(URI, Validator) ->
    get(URI, Validator, #{}).

-spec delete(hapi:uri(), yval:validator(T), hapi:req_opts()) ->
                 {ok, T | no_content} | {error, error_reason()}.
delete(URI, Validator, Opts) ->
    Ret = hapi:delete(URI, set_headers(delete, Opts)),
    process_response(Ret, Validator).

-spec post(hapi:uri(), jiffy:json_value(), yval:validator(T)) ->
                  {ok, T | no_content} | {error, error_reason()}.
post(URI, JSON, Validator) ->
    post(URI, JSON, Validator, #{}).

-spec post(hapi:uri(), jiffy:json_value(), yval:validator(T), hapi:req_opts()) ->
                  {ok, T | no_content} | {error, error_reason()}.
post(URI, JSON, Validator, Opts) ->
    Ret = hapi:post(URI, encode(JSON), set_headers(post, Opts)),
    process_response(Ret, Validator).

-spec decode(binary(), yval:validator(T)) -> {ok, T | no_content} | {error, json_error_reason()}.
decode(Data, Validator) ->
    try jiffy:decode(Data) of
        JSON ->
            case yval:validate(Validator, json_to_yaml(JSON)) of
                {ok, _} = OK ->
                    OK;
                {error, Reason, Ctx} ->
                    {error, {invalid_json, Reason, Ctx}}
            end
    catch _:_ ->
            {error, {malformed_json, Data}}
    end.

-spec encode(jiffy:json_value()) -> iodata().
encode(JSON) ->
    jiffy:encode(JSON).

-spec format_error(error_reason()) -> iolist().
format_error({invalid_json, Reason, Ctx}) ->
    io_lib:format("Unexpected JSON: ~s",
                  [yval:format_error(Reason, Ctx)]);
format_error({malformed_json, <<>>}) ->
    "Empty JSON payload";
format_error({malformed_json, Data}) ->
    io_lib:format("Malformed JSON~s", [format_non_empty(Data)]);
format_error({problem_report, #{status := Status} = Report}) ->
    io_lib:format("Problem reported with status ~B~s~s",
                  [Status,
                   format_non_empty(maps:get(title, Report, <<>>)),
                   format_non_empty(maps:get(detail, Report, <<>>))]);
format_error({status, {Status, _Headers, Body}}) ->
    io_lib:format("Unexpected response with status ~B~s",
                  [Status, format_non_empty(Body)]);
format_error(Reason) ->
    hapi:format_error(Reason).

-spec proxy_status(error_reason()) -> non_neg_integer().
proxy_status({invalid_json, _, _}) -> 400;
proxy_status({malformed_json, _}) -> 400;
proxy_status({problem_report, #{status := Status}}) -> Status;
proxy_status({status, {Status, _, _}}) -> Status;
proxy_status(Reason) -> hapi:proxy_status(Reason).

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec process_response({ok, hapi:http_reply()} | {error, hapi:error_reason()},
                       yval:validator(T)) ->
                              {ok, T} | {error, error_reason()}.
process_response({ok, {200, _, Data}}, Validator) ->
    decode(Data, Validator);
process_response({ok, {204, _, _}}, _) ->
    {ok, no_content};
process_response({ok, {Status, Headers, Data} = Reason}, _) ->
    case lists:keyfind(<<"content-type">>, 1, Headers) of
        {_, <<"application/problem+json">>} ->
            case decode(Data, problem_validator(Status)) of
                {ok, Problem} ->
                    {error, {problem_report, Problem}};
                {error, _} ->
                    {error, {status, Reason}}
            end;
        _ ->
            {error, {status, Reason}}
    end;
process_response({error, Reason}, _) ->
    {error, Reason}.

json_to_yaml([{}]) ->
    [];
json_to_yaml(L) when is_list(L) ->
    [json_to_yaml(X) || X <- L];
json_to_yaml({H}) ->
    json_to_yaml(H);
json_to_yaml({Key, Val}) ->
    {Key, json_to_yaml(Val)};
json_to_yaml(Term) ->
    Term.

-spec set_headers(hapi:method(), hapi:req_opts()) -> hapi:req_opts().
set_headers(Method, ReqOpts) ->
    Hdrs = maps:get(headers, ReqOpts, []),
    Hdrs1 = [{<<"accept">>, <<"application/json, application/problem+json">>}|Hdrs],
    Hdrs2 = case Method of
                post ->
                    [{<<"content-type">>, <<"application/json">>}|Hdrs1];
                _ ->
                    Hdrs1
            end,
    ReqOpts#{headers => Hdrs2}.

-spec format_non_empty(iodata()) -> iolist().
format_non_empty(<<>>) ->
    "";
format_non_empty([]) ->
    "";
format_non_empty(Data) ->
    [": ", truncate(Data)].

-spec truncate(binary()) -> binary().
truncate(Bin) ->
    case size(Bin) of
        Size when Size =< 1000 ->
            Bin;
        _ ->
            Bin1 = binary:part(Bin, 0, 1000),
            <<Bin1/binary, "...">>
    end.

-spec problem_validator(non_neg_integer()) -> yval:validator(problem_report()).
problem_validator(Status) ->
    yval:options(
      #{status => yval:non_neg_int(),
        type => yval:binary(),
        title => yval:binary(),
        detail => yval:binary(),
        '_' => yval:any()},
      [{return, map},
       {defaults, #{status => Status}}]).
