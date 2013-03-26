%%%=============================================================================
%%% @author Sven Heyll <sven.heyll@gmail.com>
%%% @copyright (C) 2012, Sven Heyll
%%%
%%% @doc
%%% A tracer for tracing OTP-based applications. Traces all function calls to
%%% modules of applications to a file with a human readable format.
%%% @end
%%%=============================================================================

-module(nano_trace).

-behaviour(gen_server).

%% API
-export([
         add_app/1,
         filter/0,
         filter/1,
         help/0,
         long_help/0,
         msg_depth/1,
         pause/0,
         print_applications/0,
         print_traced_functions/0,
         remove_app/1,
         resume/0,
         start/0,
         start/1,
         start/2,
         start/3,
         stop/0
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-registered([?MODULE]).

-type type() :: call | return | exception | send.

-type test() :: type() |
                {Type :: type(), Pattern :: string()} |
                {notF, test()} |
                {andF, [test()]} |
                {andF, test(), test()} |
                {orF, [test()]} |
                {orF, test(), test()} |
                string() |
                allF.

-define(DEFAULT_MSG_DEPTH, 30).
-define(LEFT_WIDTH, "50").
-define(RIGHT_WIDTH, "145").

-define(DEFAULT_IGNORED_APPS,
        [appmon, gs, kernel, mnesia, ssl, snmp, otp_mibs,
         xmerl, crypto, stdlib, public_key, observer,
         syntax_tools, tools, compiler, tv, os_mon, tv, inets, sasl,
         cowboy, ranch, hipe, siagnosis, md2, runtime_tools, webtool,
         syslog, logger, nano_trace, observer, edoc, wx, etop, asn1,
         eunit, erlymock]).
-define(MATCH_SPEC, [{'_', [], [{return_trace},{exception_trace}]}]).

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Print synopsis to stdout.
%% @end
%%------------------------------------------------------------------------------
-spec help() ->
                  helped.
help() ->
    io:format("SYNOPSIS~n"),
    io:format("================================================================================~n"),
    io:format("~n"),
    io:format("A tracer that only traces function calls to modules in a list of applications.~n"),
    io:format("For a trace that traces also messages, spawns and exits use another tracer .~n"),
    io:format("By default some applications are traced. See print_applications/0, also you can~n"),
    io:format("add and remove applications.~n"),
    io:format("~n"),
    io:format("By default the messages are cropped to prevent flooding the log file.~n"),
    io:format("To change/disable the limitation of the message depth use msg_depth/1.~n"),
    io:format("~n"),
    io:format("For a description of all functions call long_help/0.~n"),
    io:format("~n"),
    io:format("~n"),
    io:format("~n"),
    helped.

%%------------------------------------------------------------------------------
%% @doc
%% Print some help on how to use this module to stdout.
%% @end
%%------------------------------------------------------------------------------
-spec long_help() ->
                  helped.
long_help() ->
    io:format("FUNCTIONS~n"),
    io:format("=========n~n"),
    io:format("start() ->~n"),
    io:format("   {ok, pid()} | {error, term()}.~n"),
    io:format("  Start the server. The output filename is 'default-trace.log'.~n"),
    io:format("~n~n"),
    io:format("start([module()]) ->~n"),
    io:format("   {ok, pid()} | {error, term()}.~n"),
    io:format("  Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("  in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("~n~n"),
    io:format("start([module()], string()) ->~n"),
    io:format("                       {ok, pid()} | {error, term()}.~n"),
    io:format("  Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("  in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("  Second parameter is the output filename.~n"),
    io:format("~n~n"),
    io:format("start([module()], string(), test()) ->~n"),
    io:format("                       {ok, pid()} | {error, term()}.~n"),
    io:format("  Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("  in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("  Second parameter is the output filename, the third is the default filter.~n"),
    io:format("~n~n"),
    io:format("stop() ->~n"),
    io:format("                ok.~n"),
    io:format("  Stops tracing and resets all trace patterns.~n"),
    io:format("~n~n"),
    io:format("pause() ->~n"),
    io:format("                ok.~n"),
    io:format("  Pauses tracing.~n"),
    io:format("~n~n"),
    io:format("resume() ->~n"),
    io:format("                ok.~n"),
    io:format("  Resumes tracing.~n"),
    io:format("~n~n"),
    io:format("add_app(module()) ->~n"),
    io:format("   ok.~n"),
    io:format("  Add an application to tracing.~n"),
    io:format("~n~n"),
    io:format("remove_app(module()) ->~n"),
    io:format("                    ok.~n"),
    io:format("  Remove an application from tracing.~n"),
    io:format("~n~n"),
    io:format("filter(test()) ->~n"),
    io:format("                 ok.~n"),
    io:format("  Only log trace events matching an expression.~n"),
    io:format("~n~n"),
    io:format("filter() ->~n"),
    io:format("                 test().~n"),
    io:format("  Return the current filter.~n"),
    io:format("~n~n"),
    io:format("print_applications() ->~n"),
    io:format("                 ok.~n"),
    io:format("  Show the applications that are currently being traced.~n"),
    io:format("~n~n"),
    io:format("print_traced_functions() ->~n"),
    io:format("                ok.~n"),
    io:format("  Show the functions that are currently being traced.~n"),
    io:format("~n~n~n"),
    io:format("TYPES~n"),
    io:format("=====~n~n"),
    io:format("test() :: Type :: type() |~n"),
    io:format("          {Type :: type(), Pattern :: string()} |~n"),
    io:format("          {notF, test()} |~n"),
    io:format("          {andF, [test()]} |~n"),
    io:format("          {andF, test(), test()} |~n"),
    io:format("          {orF, [test()]} |~n"),
    io:format("          {orF, test(), test()} |~n"),
    io:format("          string() |~n"),
    io:format("          allF.~n"),
    io:format("~n"),
    io:format("  This type is used by find and filter, it defines the structure of~n"),
    io:format("  expressions to restrict the output of the trace log.~n"),
    io:format("~n~n"),
    io:format("type() :: call | return | exception | send.~n"),
    io:format("~n"),
    io:format("  This type is used to describe the kind of trace event, it is used~n"),
    io:format("  inside test()~n"),
    io:format("~n"),
    io:format("~n"),
    io:format("~n"),
    helped.


%%------------------------------------------------------------------------------
%% @doc
%% Start the server the trace is written to a file called "default-trace.log".
%% @end
%%------------------------------------------------------------------------------
-spec start() ->
                        {ok, pid()} | {error, term()}.
start() ->
    start(default_applications(), "default-trace.log").

%%------------------------------------------------------------------------------
%% @doc
%% Start the server. The parameter is a list of applications that are analyzed
%% in order to find out the modules, to be used as trace pattern for call trace.
%% The trace is written to a file called "trace-[date time].log".
%% @end
%%------------------------------------------------------------------------------
-spec start([module()]) ->
                        {ok, pid()} | {error, term()}.
start(Applications) ->
    start(Applications, create_file_name()).

%%------------------------------------------------------------------------------
%% @doc
%% Start the server with a custom output file name. Default filtering for
%% is applied.
%% @end
%%------------------------------------------------------------------------------
-spec start([module()], string()) ->
                        {ok, pid()} | {error, term()}.
start(Applications, FileName) ->
    start(Applications, FileName, allF).

%%------------------------------------------------------------------------------
%% @doc
%% Start the server with a custom output file name. Default filtering for
%% is applied.
%% @end
%%------------------------------------------------------------------------------
-spec start([module()], string(), test()) ->
                        {ok, pid()} | {error, term()}.
start(Applications, FileName, Filter) ->
    gen_server:start({local, ?MODULE}, ?MODULE,
                     [Applications, FileName, Filter], []).


%%------------------------------------------------------------------------------
%% @doc
%% This will add the application to the traced applications.
%% @end
%%------------------------------------------------------------------------------
-spec add_app(module()) ->
                     ok.
add_app(Application) ->
    gen_server:cast(?MODULE, {add_app, Application}).

%%------------------------------------------------------------------------------
%% @doc
%% This will remove the application from the traced applications.
%% @end
%%------------------------------------------------------------------------------
-spec remove_app(module()) ->
                     ok.
remove_app(Application) ->
    gen_server:cast(?MODULE, {remove_app, Application}).

%%------------------------------------------------------------------------------
%% @doc
%% Stops tracing and resets all trace patterns.
%% @end
%%------------------------------------------------------------------------------
-spec stop() ->
                  ok.
stop() ->
    gen_server:call(?MODULE, stop).

%%------------------------------------------------------------------------------
%% @doc
%% Pauses the tracing by removing all trace flags.
%% @end
%%------------------------------------------------------------------------------
-spec pause() ->
                  ok.
pause() ->
    gen_server:call(?MODULE, pause).

%%------------------------------------------------------------------------------
%% @doc
%% Resume the tracing by setting all trace patterns.
%% @end
%%------------------------------------------------------------------------------
-spec resume() ->
                  ok.
resume() ->
    gen_server:call(?MODULE, resume).

%%------------------------------------------------------------------------------
%% @doc
%% Define the limitation on trace message depth. This is used to crop function
%% call arguments and return values. Passing a number will define the depth
%% parameter used when formatting with "~P" ... [Depth], passing 'unlimited' will
%% format the messages with "~p".
%% @see io:fwrite/2
%% @end
%%------------------------------------------------------------------------------
-spec msg_depth(non_neg_integer() | unlimited) ->
                       ok.
msg_depth(Depth) ->
    gen_server:call(?MODULE, {msg_depth, Depth}).

%%------------------------------------------------------------------------------
%% @doc
%% Set a new filter for trace events to be logged.
%% @end
%%------------------------------------------------------------------------------
-spec filter(test()) ->
                  [string()].
filter(Test) ->
    case check_test(Test) of
        true ->
            gen_server:call(?MODULE, {filter, Test}, infinity);
        false ->
            throw(invalid_trace_test)
    end.

%%------------------------------------------------------------------------------
%% @doc
%% Return the current filter
%% @end
%%------------------------------------------------------------------------------
-spec filter() ->
             test().
filter() ->
    gen_server:call(?MODULE, get_filter, infinity).

%%------------------------------------------------------------------------------
%% @doc
%% Print a list of applications to be traced.
%% @end
%%------------------------------------------------------------------------------
-spec print_applications() ->
                  ok.
print_applications() ->
    Apps = gen_server:call(?MODULE, get_applications),
    io:format("~nTraced applications:~n~p~n~n", [Apps]).

%%------------------------------------------------------------------------------
%% @doc
%% Print a list of functions that are traced.
%% @end
%%------------------------------------------------------------------------------
-spec print_traced_functions() ->
                  ok.
print_traced_functions() ->
    Funs = gen_server:call(?MODULE, get_traced_functions),
    io:format("~nTraced functions:~n~p~n~n", [Funs]).

%%------------------------------------------------------------------------------
%% @doc
%% Returns `true' if the test expression is valid.
%% @end
%%------------------------------------------------------------------------------
-spec check_test(test()) ->
                     boolean().
check_test({call, Str}) when is_list(Str) ->
    true;
check_test(call) ->
    true;
check_test({return, Str}) when is_list(Str) ->
    true;
check_test(return) ->
    true;
check_test({exception, Str}) when is_list(Str) ->
    true;
check_test(exception) ->
    true;
check_test({send, Str}) when is_list(Str) ->
    true;
check_test(send) ->
    true;
check_test({F, []}) when F == orF orelse F == andF ->
    true;
check_test({F, [Test | Tests]}) when F == orF orelse F == andF  ->
    check_test(Test) andalso check_test({F, Tests});
check_test({F, Test1, Test2}) when  F == orF orelse F == andF  ->
    check_test(Test1) andalso check_test(Test2);
check_test({notF, Test}) ->
    check_test(Test);
check_test(allF) ->
    true;
check_test(SearchStr) when is_list(SearchStr) ->
    true;
check_test(_) ->
    false.

%%%=============================================================================
%%% gen_server Callbacks
%%%=============================================================================

-record(state, {
          applications   = []                 :: [atom()],
          trace_active   = false              :: boolean(),
          trace_patterns = []                 :: [{module(), '_', '_'}],
          filter         = allF               :: test(),
          depth          = ?DEFAULT_MSG_DEPTH :: non_neg_integer() | unlimited,
          io_device}).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
init([Applications, FileName, Filter]) ->
    process_flag(sensitive, true),
    {ok, IoDevice} = file:open(FileName, [append]),
    State = #state{
      trace_active   = false,
      filter         = Filter,
      applications   = Applications,
      trace_patterns = [],
      io_device      = IoDevice},
    {ok, resume_tracing(State)}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call({msg_depth, Depth}, _From, State) ->
    {reply, ok, State#state{depth = Depth}};

handle_call({filter, Filter}, _From, State) ->
    {reply, ok, State#state{filter = Filter}};

handle_call(get_filter, _From, State) ->
    {reply, State#state.filter, State};

handle_call(get_applications, _From, State) ->
    {reply, State#state.applications, State};

handle_call(get_traced_functions, _From, State) ->
    {reply, [{M,F} || {M,F,_} <- State#state.trace_patterns], State};

handle_call(pause, _From, State) ->
    {reply, ok, pause_tracing(State)};

handle_call(resume, _From, State) ->
    {reply, ok, resume_tracing(State)}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
handle_cast({add_app, Application}, State) ->
    NewApps = lists:usort([Application | State#state.applications]),
    NewState = update_trace_config(
                 State#state{applications = NewApps}),
    {noreply, NewState};

handle_cast({remove_app, Application}, State) ->
    NewApps = lists:usort(State#state.applications -- [Application]),
    NewState = update_trace_config(
                 State#state{applications = NewApps}),
    {noreply, NewState}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
handle_info(Trace, State = #state{filter    = Filter,
                                  io_device = IoDevice,
                                  depth     = Depth})
  when is_tuple(Trace) andalso element(1, Trace) =:= trace_ts ->
    if
        State#state.trace_active ->
            Msg = lists:flatten(
                         [M || T = {_, M} <- format(Trace, Depth),
                               filter(Filter, T)]),
            file:write(IoDevice, Msg),
            {noreply, State};

        true ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
terminate(_Reason, State) ->
    pause_tracing(State),
    file:close(State#state.io_device),
    ok.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%=============================================================================
%%% Internal Functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec get_modules([module()]) ->
                         [module()].
get_modules(Applications) ->
    lists:foldl(
      fun(Application, Acc) ->
	      case application:get_key(Application, modules) of
		  {ok, Modules} ->
                      {ok, Vsn} = application:get_key(Application, vsn),
                      {ok, Title} = application:get_key(Application, description),
                      io:format("Tracing application ~s ~s (~w modules)~n     ~s~n~n",
                                [Application, Vsn, length(Modules), Title]),

		      Acc ++ Modules;

		  undefined ->
		      Acc
	      end
      end, [], Applications).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec get_trace_patterns([module()]) ->
                                [{module(), '_', '_'}].
get_trace_patterns(Modules) ->
    [{Module, '_', '_'} || Module <- Modules].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec format(term(), non_neg_integer() | unlimited) ->
		    [{type(), string()}].
format({trace_ts, Pid, send, Msg, To, TimeStamp}, Depth) ->
    [{send,
      format_send(TimeStamp, Pid, Msg, To, Depth)}];

format({trace_ts, Pid, send_to_non_existing_process, Msg, To, TimeStamp},
       Depth) ->
    [{send,
      format_send_non_existing(TimeStamp, Pid, Msg, To, Depth)}];

format({trace_ts, Pid, call, {M,F,A}, TimeStamp}, Depth) ->
    [{call,
      format(">>>", TimeStamp, Pid,
             {M, F, length(A)}, "applied to", A, Depth)}];

format({trace_ts, Pid, return_from, {M,F,A}, RV, TimeStamp}, Depth) ->
    [{return,
      format("<<<", TimeStamp, Pid,
             {M, F, A}, "returned", RV, Depth)}];

format({trace_ts, Pid, return_to, {M,F,A}, TimeStamp}, Depth) ->
    [{return,
      format("<<<", TimeStamp, Pid,
             {M,F,A}, "was returned to", "", Depth)}];

format({trace_ts, Pid, exception_from, {M,F,A}, Exc, TimeStamp}, Depth) ->
    [{exception,
      format("*** EXCEPTION ***", TimeStamp, Pid,
             {M,F,A}, "threw", Exc, Depth)}];

format(_, _) ->
    [].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format_send(When, Pid, Msg, To, Depth) ->
    WhenStr = format_time(When),
    Dest = lists:flatten(io_lib:format("~w", [To])),
    format_cropped(" ! ", WhenStr, Pid, " sends to ", Dest, Msg, Depth).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format_send_non_existing(When, Pid, Msg, To, Depth) ->
    WhenStr = format_time(When),
    Dest = lists:flatten(io_lib:format("~w", [To])),
    format_cropped("*!*", WhenStr, Pid, " sends to DEAD PROCESS ", Dest, Msg,
                   Depth).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format(Symbol, When, Pid, Func, Action, Arg, Depth) ->
    WhenStr = format_time(When),
    FuncStr = format_func(Func),
    format_cropped(Symbol, WhenStr, Pid, FuncStr, Action, Arg, Depth).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format_cropped(Symbol, WhenStr, Pid, FuncStr, Action, Arg, unlimited) ->
    lists:flatten(
      io_lib:format(
	"~s ~s ~-15w ~-"++ ?LEFT_WIDTH ++"s ~15s: ~"++ ?RIGHT_WIDTH ++"p~n~n",
	[Symbol, WhenStr, Pid, FuncStr, Action, Arg]));

format_cropped(Symbol, WhenStr, Pid, FuncStr, Action, Arg, Depth) ->
    lists:flatten(
      io_lib:format(
	"~s ~s ~-15w ~-"++ ?LEFT_WIDTH ++"s ~15s: ~"++ ?RIGHT_WIDTH ++"P~n~n",
	[Symbol, WhenStr, Pid, FuncStr, Action, Arg, Depth])).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format_func({M,F,A}) ->
    lists:flatten(io_lib:format("~p:~p/~p", [M, F, A])).


%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format_time(Now) ->
    {{YYYY, MM, DD}, {HH, Mm, SS}} = calendar:now_to_local_time(Now),
    {_,_,MuSecs} = Now,
    Millis = (MuSecs div 1000) rem 1000,
    lists:flatten(
        io_lib:format(
          "~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w,~3..0w",
	[YYYY, MM, DD, HH, Mm, SS, Millis])).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec filter(test(), {type(), string()}) ->
                     boolean().
filter({TestType, TestPattern}, {TraceType, TraceMsg})
  when TestType == TraceType ->
    matches(TraceMsg, TestPattern);

filter(TestType, {TraceType, _})
  when TestType == TraceType ->
    true;

filter({andF, []}, _) ->
    true;
filter({andF, [Test | Tests]}, Trace) ->
    filter(Test, Trace) andalso filter({andF, Tests}, Trace);
filter({andF, Test1, Test2}, Trace) ->
    filter(Test1, Trace) andalso filter(Test2, Trace);

filter({orF, []}, _) ->
    false;
filter({orF, [Test | Tests]}, Trace) ->
    filter(Test, Trace) orelse filter({orF, Tests}, Trace);
filter({orF, Test1, Test2}, Trace) ->
    filter(Test1, Trace) orelse filter(Test2, Trace);

filter({notF, Test}, Trace) ->
    not filter(Test, Trace);

filter(allF, _) ->
    true;

% match string
filter(Test, {_, Trace}) when is_list(Test) ->
    matches(Trace, Test);

filter(_, _) ->
    false.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec matches(string(), string()) ->
		     boolean().
matches(Msg, Pattern) ->
    string:str(Msg, Pattern) > 0.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
update_trace_config(#state{trace_active = false} = S) ->
    S;
update_trace_config(S) ->
    io:format("~n~n+++ TRACING RECONFIGURATION BEGIN +++~n~n"),
    NewS = resume_tracing(pause_tracing(S)),
    io:format("~n~n+++ TRACING RECONFIGURATION END +++~n~n"),
    NewS.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
resume_tracing(#state{trace_active = true} = S) ->
    S;
resume_tracing(#state{applications = Applications} = S) ->
    enable_send_tracing(Applications),
    Patterns = enable_call_tracing(Applications),
    %% set the excludes
    catch erlang:trace(self(), false, [all]),
    io:format("~n~n+++ TRACING ENABLED +++~n~n"),
    S#state{trace_active   = true,
            trace_patterns = Patterns}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
pause_tracing(#state{trace_active = false} = S) ->
    S;
pause_tracing(S) ->
    %% reset all trace patterns
    disable_tracing(),
    io:format("~n~n+++ TRACING DISABLED +++~n~n"),
    S#state{trace_active = false}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
create_file_name() ->
    {{YYYY, MM, DD}, {HH, Mm, SS}} = calendar:now_to_local_time(now()),
    Timestamp =
        lists:flatten(
          io_lib:format(
            "~4..0w-~2..0w-~2..0w-~2..0w-~2..0w-~2..0w",
            [YYYY, MM, DD, HH, Mm, SS])),
    "trace-" ++ Timestamp.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
default_applications() ->
    IgnoredApps = ?DEFAULT_IGNORED_APPS,
    [A || {A, _, _} <- application:loaded_applications(),
                 not lists:member(A, IgnoredApps)].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
enable_call_tracing(Applications) ->
    Modules = get_modules(Applications),
    Patterns = get_trace_patterns(Modules),
    %% set the patterns
    [catch erlang:trace_pattern(MFA, ?MATCH_SPEC, []) || MFA <- Patterns],

    %% set the function trace
    catch erlang:trace(all, true, [call, timestamp, return_to]),
    Patterns.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
enable_send_tracing(Applications) ->
    [catch erlang:trace(Pid, true, ['receive', send, set_on_spawn]) ||
        Pid <- get_applications_pids(Applications)].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
get_applications_pids(Applications) ->
    [Pid || Pid <- processes(),
            {ok, App} <- [application:get_application(Pid)],
            lists:member(App, Applications)].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
disable_tracing() ->
    catch erlang:trace_pattern({'_', '_', '_'}, false, []),
    catch erlang:trace(all, false, [all]).
