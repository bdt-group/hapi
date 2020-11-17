%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created :  2 Nov 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_misc).

%% API
-export([format_addr/1]).
-export([current_time/0]).
-export([timeout/1]).
-export([defaults/0]).
-export([default/1]).
-export([get_env_pos_int/1]).
-export_type([millisecs/0]).

-type millisecs() :: non_neg_integer().
-type env() :: pool_size | max_queue.

%%%===================================================================
%%% API
%%%===================================================================
-spec format_addr(inet:ip_address()) -> string().
format_addr({_, _, _, _} = IPv4) ->
    inet:ntoa(IPv4);
format_addr({_, _, _, _, _, _, _, _} = IPv6) ->
    "[" ++ inet:ntoa(IPv6) ++ "]".

-spec current_time() -> millisecs().
current_time() ->
    os:system_time(millisecond).

-spec timeout(millisecs()) -> non_neg_integer().
timeout(DeadLine) ->
    max(0, DeadLine - current_time()).

-spec defaults() -> #{env() => term()}.
defaults() ->
    #{pool_size => 10,
      max_queue => 10000}.

-spec default(env()) -> term().
default(Env) ->
    maps:get(Env, defaults()).

-spec get_env_pos_int(env()) -> pos_integer().
get_env_pos_int(Opt) ->
    case application:get_env(hapi, Opt) of
        {ok, I} when is_integer(I), I > 0 -> I;
        undefined -> default(Opt);
        {ok, Junk} ->
            erlang:error({bad_option_value, Opt, Junk})
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
