%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 29 Oct 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([start_child/3]).
-export([stop_child/1]).
%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_child(term(), module(), list()) ->
                         {ok, pid()} | {error, term()}.
start_child(Name, Mod, Args) ->
    Spec = #{id => Name,
             start => {Mod, start_link, Args},
             restart => transient,
             shutdown => 5000,
             type => worker,
             modules => [Mod]},
    case supervisor:start_child(?MODULE, Spec) of
        {ok, _} = OK -> OK;
        {error, {already_started, Pid}} -> {ok, Pid};
        Err -> Err
    end.

-spec stop_child(term()) -> ok | {error, term()}.
stop_child(Name) ->
    case supervisor:terminate_child(?MODULE, Name) of
        ok ->
            supervisor:delete_child(?MODULE, Name);
        Err ->
            Err
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================
-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{strategy => one_for_one,
                 intensity => 10,
                 period => 1},
    {ok, {SupFlags, []}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
