%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 29 Oct 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_yaml).

%% API
-export([validator/0]).
%% Imported validators
-import(yval, [options/2, pos_int/0]).

%%%===================================================================
%%% API
%%%===================================================================
-spec validator() -> yval:validator().
validator() ->
    options(
      #{pool_size => pos_int(),
        max_queue => pos_int()},
      [unique, {defaults, hapi_misc:defaults()}]).

%%%===================================================================
%%% Internal functions
%%%===================================================================
