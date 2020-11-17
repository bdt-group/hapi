%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2020, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created : 28 Oct 2020 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(hapi_pool).

-behaviour(gen_server).

%% API
-export([start/2, stop/1]).
-export([start_link/2]).
-export([open/3, close/3]).
%% API for tests only
-export([get_state/1]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").

-record(state, {addr                     :: inet:ip_address(),
                port                     :: inet:port_number(),
                opts                     :: gun_opts(),
                idle = []                :: [connection_pid()],
                busy = #{}               :: #{connection_pid() => {caller(), timer_ref(), deadline()}},
                connections = #{}        :: #{connection_pid() => {monitor_ref(), protocol()}},
                callers = #{}            :: #{caller_pid() => {monitor_ref(), counter()}},
                rq = queue:new()         :: request_queue(),
                rq_size = 0              :: non_neg_integer(),
                last_overload_report = 0 :: hapi_misc:millisecs()}).

-type state() :: #state{}.
-type pool() :: atom() | pid().
-type connection_pid() :: pid().
-type caller_pid() :: pid().
-type caller() :: {caller_pid(), reference()}.
-type timer_ref() :: reference().
-type monitor_ref() :: reference().
-type counter() :: pos_integer().
-type deadline() :: hapi_misc:millisecs().
-type protocol() :: atom().
-type request_queue() :: queue:queue({caller(), deadline()}).
-type error_reason() :: timeout | closed | overloaded | term().
-type addr_port() :: {inet:ip_address(), inet:port_number()}.
-type noreply() :: {noreply, state()}.
%% We should have used gun:opts(), but this leads to a Dialyzer warning
%% due to missing export of ssl:connect_option/0
-type gun_opts() :: map().

%%%===================================================================
%%% API
%%%===================================================================
-spec start(addr_port(), gun_opts()) -> {ok, pid()} | {error, term()}.
start(AddrPort, Opts) ->
    hapi_sup:start_child(AddrPort, ?MODULE, [AddrPort, Opts]).

-spec stop(addr_port()) -> ok.
stop(AddrPort) ->
    _ = hapi_sup:stop_child(AddrPort),
    ok.

-spec start_link(addr_port(), gun_opts()) -> {ok, pid()} | {error, term()}.
start_link(AddrPort, Opts) ->
    Proc = list_to_atom(pool_name(AddrPort)),
    gen_server:start_link({local, Proc}, ?MODULE, {AddrPort, Opts}, []). %%[{debug, [trace]}]).

-spec open(addr_port(), gun_opts(), deadline()) ->
                  {ok, connection_pid()} | {error, error_reason()}.
open({_, _} = AddrPort, Opts, DeadLine) ->
    Proc = list_to_atom(pool_name(AddrPort)),
    case open(Proc, DeadLine) of
        {error, pool_not_started} ->
            case start(AddrPort, Opts) of
                {ok, _} -> open(Proc, DeadLine);
                {error, _} = Err -> Err
            end;
        Ret ->
            Ret
    end.

-spec open(pool(), deadline()) -> {ok, connection_pid()} | {error, error_reason()}.
open(Proc, DeadLine) ->
    try gen_server:call(Proc, {open, DeadLine}, hapi_misc:timeout(DeadLine))
    catch _:{noproc, {gen_server, call, _}} -> {error, pool_not_started};
          _:{timeout, {gen_server, call, _}} -> {error, timeout};
          _:{_, {gen_server, call, _}} -> {error, closed}
    end.

-spec close(addr_port(), connection_pid(), reference() | undefined) -> ok.
close(AddrPort, ConnPid, StreamRef) ->
    case is_reference(StreamRef) of
        true -> gun:cancel(ConnPid, StreamRef);
        false -> ok
    end,
    try list_to_existing_atom(pool_name(AddrPort)) of
        Proc ->
            gen_server:cast(Proc, {close, ConnPid, self()})
    catch _:badarg ->
            ok
    end.

-spec get_state(addr_port()) -> map().
get_state(AddrPort) ->
    Proc = list_to_existing_atom(pool_name(AddrPort)),
    [_|State] = tuple_to_list(sys:get_state(Proc)),
    maps:from_list(lists:zip(record_info(fields, state), State)).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init({addr_port(), gun_opts()}) -> {ok, state()}.
init({{Addr, Port}, Opts}) ->
    process_flag(trap_exit, true),
    {ok, #state{addr = Addr, port = Port, opts = Opts}}.

-spec handle_call({open, deadline()} | term(), caller(), state()) -> noreply().
handle_call({open, DeadLine}, {CallerPid, _} = Caller,
            #state{idle = [ConnPid|Idle]} = State) ->
    %% We have an idle connection in the pool
    case reply(Caller, {ok, ConnPid}, DeadLine) of
        false ->
            %% The caller's deadline has been reached.
            %% Jump to the next awaiting caller
            dequeue(State);
        true ->
            {_, Protocol} = maps:get(ConnPid, State#state.connections),
            %% Send fake `gun_up` to replicate hapi's normal flow
            %% and make the connection busy by the caller
            CallerPid ! {gun_up, ConnPid, Protocol},
            State1 = acquire_connection(Caller, ConnPid, DeadLine,
                                        State#state{idle = Idle}),
            noreply(State1)
    end;
handle_call({open, DeadLine}, Caller, State) ->
    %% No idle connections found, fire a new one (if the pool is not full)
    %% and enqueue the caller: once the new connection is established
    %% we dequeue the caller (see `gun_up` message processing).
    %% If the pool is full and, thus, we haven't started a new connection,
    %% the caller will be dequeued later when some busy connection is released.
    case start_connection(State) of
        {ok, State1} ->
            enqueue({Caller, DeadLine}, State1);
        {{error, _} = Err, State1} ->
            reply(Caller, Err, DeadLine),
            noreply(State1)
    end;
handle_call(Request, {Pid, _}, State) ->
    ?LOG_WARNING("Unexpected call from ~p: ~p", [Pid, Request]),
    noreply(State).

-spec handle_cast(term(), state()) -> noreply().
handle_cast({close, ConnPid, CallerPid}, State) ->
    State1 = release_connection(CallerPid, ConnPid, State),
    dequeue(State1);
handle_cast(Request, State) ->
    ?LOG_WARNING("Unexpected cast: ~p", [Request]),
    noreply(State).

-spec handle_info(term(), state()) -> noreply().
handle_info({gun_up, ConnPid, Protocol}, State) ->
    case maps:find(ConnPid, State#state.connections) of
        {ok, {Monitor, _Protocol = undefined}} ->
            Connections = maps:put(ConnPid, {Monitor, Protocol}, State#state.connections),
            State1 = State#state{connections = Connections},
            State2 = set_idle(ConnPid, State1),
            dequeue(State2);
        _ ->
            %% Late arrival of `gun_up`? But is it even possible?
            noreply(State)
    end;
handle_info({'DOWN', MRef, process, Pid, _Reason}, State) ->
    %% First, check whether the pid is a connection pid
    case maps:take(Pid, State#state.connections) of
        {{MRef, _Protocol}, Connections} ->
            State1 = State#state{connections = Connections},
            State2 = handle_connection_down(Pid, State1),
            dequeue(State2);
        _ ->
            %% Now check whether the pid is a caller's pid
            case maps:take(Pid, State#state.callers) of
                {{MRef, _}, Callers} ->
                    State1 = handle_caller_down(Pid, State#state{callers = Callers}),
                    dequeue(State1);
                _ ->
                    %% Late arrival of the monitor event: we don't
                    %% flush during demonitor for the sake of performance,
                    %% so this might happen
                    noreply(State)
            end
    end;
handle_info({timeout, Timer, {ConnPid, CallerPid}}, State) ->
    case maps:find(ConnPid, State#state.busy) of
        {ok, {{CallerPid, _}, Timer, _DeadLine}} ->
            State1 = release_connection(CallerPid, ConnPid, State),
            dequeue(State1);
        _ ->
            %% Late arrival of the timeout: we don't use synchronous
            %% cancellation for the sake of performance, so this might happen
            noreply(State)
    end;
%% Ignore gun_down/gun_error: we rely on 'DOWN' messages instead
handle_info({gun_down, _, _, _, _, _}, State) ->
    noreply(State);
handle_info({gun_error, _, _}, State) ->
    noreply(State);
handle_info({gun_error, _, _, _}, State) ->
    noreply(State);
handle_info(Info, State) ->
    ?LOG_WARNING("Unexpected info: ~p", [Info]),
    noreply(State).

-spec terminate(term(), state()) -> ok.
terminate(_Reason, State) ->
    State1 = discard_all_requests(closed, State),
    lists:foreach(
      fun(ConnPid) ->
              gun:close(ConnPid)
      end, maps:keys(State1#state.connections)).

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Connections/callers management
%%%===================================================================
-spec start_connection(state()) -> {ok | {error, term()}, state()}.
start_connection(State) ->
    case maps:size(State#state.connections) >= pool_size() of
        true ->
            {ok, State};
        false ->
            case gun:open(State#state.addr, State#state.port, State#state.opts) of
                {ok, ConnPid} ->
                    MonitorProtocol = {erlang:monitor(process, ConnPid), undefined},
                    Connections = maps:put(ConnPid, MonitorProtocol,
                                           State#state.connections),
                    {ok, State#state{connections = Connections}};
                {error, Reason} = Err ->
                    ?LOG_ERROR("Failed to open connection to ~s:~B due to "
                               "internal error: ~p",
                               [hapi_misc:format_addr(State#state.addr),
                                State#state.port, Reason]),
                    {Err, State}
            end
    end.

-spec stop_connection(connection_pid(), state()) -> state().
stop_connection(ConnPid, State) ->
    case maps:take(ConnPid, State#state.connections) of
        {{Monitor, _}, Connections} ->
            erlang:demonitor(Monitor),
            gun:close(ConnPid),
            State#state{connections = Connections};
        error ->
            State
    end.

-spec acquire_connection(caller(), connection_pid(), deadline(), state()) -> state().
acquire_connection({CallerPid, _} = Caller, ConnPid, DeadLine, State) ->
    %% If we are not monitoring the caller's pid then start doing so.
    %% Otherwise, just bump the monitor reference counter
    %% This shit is needed because a single caller might issue many requests
    %% and we don't want to spawn 100500 monitors for the same process
    {Monitor, Counter} = case maps:find(CallerPid, State#state.callers) of
                             {ok, MC} -> MC;
                             error -> {erlang:monitor(process, CallerPid), 0}
                         end,
    Callers = maps:put(CallerPid, {Monitor, Counter+1}, State#state.callers),
    Timer = erlang:start_timer(hapi_misc:timeout(DeadLine), self(), {ConnPid, CallerPid}),
    %% Mark the connection as busy by the caller
    Busy = maps:put(ConnPid, {Caller, Timer, DeadLine}, State#state.busy),
    State#state{busy = Busy, callers = Callers}.

-spec release_connection(caller_pid(), connection_pid(), state()) -> state().
release_connection(CallerPid, ConnPid, State) ->
    %% If monitor reference counter is 1, then demonitor the caller's pid
    %% and drop it from the `callers` table. Otherwise, decrement the counter.
    %% This shit is needed because a single caller might issue many requests
    %% and we don't want to spawn 100500 monitors for the same process
    Callers = case maps:find(CallerPid, State#state.callers) of
                  {ok, {Monitor, Counter}} when Counter > 1 ->
                      maps:put(CallerPid, {Monitor, Counter-1}, State#state.callers);
                  {ok, {Monitor, _}} ->
                      erlang:demonitor(Monitor),
                      maps:remove(CallerPid, State#state.callers);
                  error ->
                      State#state.callers
              end,
    State1 = State#state{callers = Callers},
    %% If the connection is busy, cancel the request timer and mark it as idle
    %% Otherwise, do nothing (this might happen e.g. due to late arrivale of close request)
    case maps:take(ConnPid, State#state.busy) of
        {{{CallerPid, _}, Timer, _DeadLine}, Busy} ->
            cancel_timer(Timer),
            State2 = State1#state{busy = Busy},
            set_idle(ConnPid, State2);
        _ ->
            State1
    end.

-spec handle_connection_down(connection_pid(), state()) -> state().
handle_connection_down(ConnPid, State) ->
    %% Connection is down
    %% If the connection is busy, release it.
    State1 = case maps:find(ConnPid, State#state.busy) of
                 error -> State;
                 {ok, {{CallerPid, _}, _Timer, _DeadLine}} ->
                     release_connection(CallerPid, ConnPid, State)
             end,
    %% In any case we remove the connection from the `idle` list.
    Idle = lists:delete(ConnPid, State1#state.idle),
    State1#state{idle = Idle}.

-spec handle_caller_down(caller_pid(), state()) -> state().
handle_caller_down(CallerPid, State) ->
    %% Caller is down
    %% Move all caller's connections from `busy` table to `idle` list
    {Busy1, State1} =
        maps:fold(
          fun(ConnPid, {{Pid, _}, Timer, _DeadLine}, {AccBusy, AccState})
                when Pid == CallerPid ->
                  cancel_timer(Timer),
                  {maps:remove(ConnPid, AccBusy), set_idle(ConnPid, AccState)};
             (_, _, Acc) ->
                  Acc
          end, {State#state.busy, State}, State#state.busy),
    State1#state{busy = Busy1}.

-spec set_idle(connection_pid(), state()) -> state().
set_idle(ConnPid, State) ->
    %% The pool size might have been decreased by reconfiguration:
    %% we check it before bringing the connection back to `idle` list
    case maps:size(State#state.connections) > pool_size() of
        true ->
            stop_connection(ConnPid, State);
        false ->
            Idle = [ConnPid | State#state.idle],
            State#state{idle = Idle}
    end.

%% Only reply when deadline is not reached in order
%% to avoid response arrival after gen_server:call/3 timeout
-spec reply(caller(), term(), deadline()) -> boolean().
reply(Caller, Term, DeadLine) ->
    case hapi_misc:current_time() < DeadLine of
        false -> false;
        true ->
            gen_server:reply(Caller, Term),
            true
    end.

%%%===================================================================
%%% Request queue management
%%%===================================================================
-spec enqueue({caller(), deadline()}, state()) -> noreply().
enqueue(Request, State) ->
    State3 = case is_overloaded(State) of
                 false -> State;
                 true ->
                     State1 = report_overload(State),
                     State2 = drop_stale_requests(State1),
                     %% Check that at least 20% of requests have been dropped
                     case is_overloaded(State2, 0.8) of
                         true -> discard_all_requests(overloaded, State2);
                         false -> State2
                     end
             end,
    RQ = queue:in(Request, State3#state.rq),
    Size = State3#state.rq_size + 1,
    noreply(State3#state{rq = RQ, rq_size = Size}).

-spec dequeue(state()) -> noreply().
dequeue(#state{rq_size = Size} = State) when Size > 0 ->
    case State#state.idle of
        [_|_] ->
            {{value, {Caller, DeadLine}}, RQ} = queue:out(State#state.rq),
            handle_call({open, DeadLine}, Caller, State#state{rq = RQ, rq_size = Size - 1});
        [] ->
            %% The pool size might have been increased by reconfiguration
            %% or a previous connections might have been failed:
            %% we try to start a new connection here -- if the pool is not
            %% full, it will be started, otherwise nothing will happen.
            %% Once the connection is established we will call dequeue
            %% again (see `gun_up` message processing)
            {_, State1} = start_connection(State),
            noreply(State1)
    end;
dequeue(State) ->
    noreply(State).

-spec discard_all_requests(error_reason(), state()) -> state().
discard_all_requests(Reason, State) ->
    _ = queue:filter(
          fun({Caller, DeadLine}) ->
                  _ = reply(Caller, {error, Reason}, DeadLine),
                  false
          end, State#state.rq),
    State#state{rq = queue:new(), rq_size = 0}.

-spec drop_stale_requests(state()) -> state().
drop_stale_requests(State) ->
    CurrTime = hapi_misc:current_time(),
    RQ = queue:filter(
           fun({_Caller, DeadLine}) ->
                   CurrTime < DeadLine
           end, State#state.rq),
    State#state{rq = RQ, rq_size = queue:len(RQ)}.

-spec is_overloaded(state()) -> boolean().
is_overloaded(State) ->
    is_overloaded(State, 1.0).

-spec is_overloaded(state(), float()) -> boolean().
is_overloaded(#state{rq_size = Size}, Ratio) ->
    Size >= Ratio * max_queue().

-spec report_overload(state()) -> state().
report_overload(State) ->
    Time = hapi_misc:current_time(),
    LastTime = State#state.last_overload_report,
    case (Time - LastTime) >= timer:seconds(30) of
        true ->
            ?LOG_WARNING("HTTP connection pool to ~s:~B is overloaded "
                         "(pending request queue size = ~B, limit = ~p)",
                         [hapi_misc:format_addr(State#state.addr),
                          State#state.port,
                          State#state.rq_size, max_queue()]),
            State#state{last_overload_report = Time};
        false ->
            State
    end.

%%%===================================================================
%%% Application environment
%%%===================================================================
-spec pool_size() -> pos_integer().
pool_size() ->
    hapi_misc:get_env_pos_int(?FUNCTION_NAME).

-spec max_queue() -> pos_integer().
max_queue() ->
    hapi_misc:get_env_pos_int(?FUNCTION_NAME).

%%%===================================================================
%%% Misc
%%%===================================================================
-spec pool_name(addr_port()) -> string().
pool_name({Addr, Port}) ->
    ?MODULE_STRING ++ "_" ++ hapi_misc:format_addr(Addr) ++ ":" ++ integer_to_list(Port).

-spec cancel_timer(reference()) -> ok.
cancel_timer(Timer) ->
    _ = erlang:cancel_timer(Timer, [{async, true}, {info, false}]),
    ok.

-spec noreply(state()) -> noreply().
noreply(State) ->
    {noreply, State}.
