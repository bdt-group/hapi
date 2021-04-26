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
