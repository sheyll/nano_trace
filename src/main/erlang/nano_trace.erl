%%%=============================================================================
%%% @author Sven Heyll <sven.heyll@gmail.com>
%%% @copyright (C) 2012, Sven Heyll
%%%
%%% @doc
%%% A tracer for tracing OTP-based applications. Traces all function calls to
%%% modules of applications to a file with a human readable format.
%%% @end
%%%=============================================================================

-module(lbm_tracer).

-behaviour(gen_server).

%% API
-export([help/0,
         long_help/0,
         add_app/1,
         filter/1,
         filter/0,
         lbm_filter/0,
         remove_app/1,
         start/0,
         start/1,
         start/2,
         start/3,
         pause/0,
         resume/0,
         stop/0,
         print_applications/0,
         print_traced_functions/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-registered([?MODULE]).

-type type() :: call | return | exception.

-type test() :: type() |
                {Type :: type(), Pattern :: string()} |
                {notF, test()} |
                {andF, [test()]} |
                {andF, test(), test()} |
                {orF, [test()]} |
                {orF, test(), test()} |
                string() |
                allF.

-define(FLAGS, [call, timestamp, return_to]).

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
    io:format("A tracer that only traces function calls to modules in a list of applications.n"),
    io:format("For a trace that traces also messages, spawns and exits use another tracer .~n"),
    io:format("By default only events matching lbm_tracer:lbm_filter()  are recoreded.~n"),
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
    io:format("================================================================================~n"),
    io:format("start() ->~n"),
    io:format("   {ok, pid()} | {error, term()}.~n"),
    io:format("Start the server. The most important mrf applications are traced with~n"),
    io:format("lbm_filter, also the output filename is 'default-trace.log'.~n"),
    io:format("~n~n"),
    io:format("start([module()]) ->~n"),
    io:format("   {ok, pid()} | {error, term()}.~n"),
    io:format("Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("~n~n"),
    io:format("start([module()], string()) ->~n"),
    io:format("                       {ok, pid()} | {error, term()}.~n"),
    io:format("Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("Second parameter is the output filename.~n"),
    io:format("~n"),
    io:format("start([module()], string(), test()) ->~n"),
    io:format("                       {ok, pid()} | {error, term()}.~n"),
    io:format("Start the server. The parameter is a list of applications that are analyzed~n"),
    io:format("in order to find out the modules, to be used as trace pattern for call trace.~n"),
    io:format("Second parameter is the output filename, the third is the default filter.~n"),
    io:format("~n~n"),
    io:format("stop() ->~n"),
    io:format("                ok.~n"),
    io:format("Stops tracing and resets all trace patterns.~n"),
    io:format("~n~n"),
    io:format("pause() ->~n"),
    io:format("                ok.~n"),
    io:format("Pauses tracing.~n"),
    io:format("~n~n"),
    io:format("resume() ->~n"),
    io:format("                ok.~n"),
    io:format("Resumes tracing.~n"),
    io:format("~n~n"),
    io:format("add_app(module()) ->~n"),
    io:format("   ok.~n"),
    io:format("This will add the application to the traced applications.~n"),
    io:format("~n~n"),
    io:format("remove_app(module()) ->~n"),
    io:format("                    ok.~n"),
    io:format("This will remove the application from the traced applications.~n"),
    io:format("~n~n"),
    io:format("filter(test()) ->~n"),
    io:format("                 ok.~n"),
    io:format("Only trace events matching an expression.~n"),
    io:format("~n~n"),
    io:format("filter() ->~n"),
    io:format("                 test().~n"),
    io:format("Return the current filter.~n"),
    io:format("~n~n"),
    io:format("lbm_filter() ->~n"),
    io:format("                 test().~n"),
    io:format("Return a filter that is well suited for internal testing.~n"),
    io:format("~n~n"),
    io:format("print_applications() ->~n"),
    io:format("                 [atom()].~n"),
    io:format("Print a list of applications to be traced.~n"),
    io:format("~n~n"),
    io:format("print_traced_functions() ->~n"),
    io:format("                 [{module(), atom()}].~n"),
    io:format("Print a list of functions that are traced.~n"),
    io:format("~n~n"),
    io:format("TYPES~n"),
    io:format("================================================================================~n"),
    io:format("~n"),
    io:format("This type is used by find and filter, it defines the structure of~n"),
    io:format("expressions to restrict the output of the trace log.~n"),
    io:format("~n"),
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
    io:format("This type is used to describe the kind of trace event, it is used~n"),
    io:format("inside test()~n"),
    io:format("~n"),
    io:format("type() :: call | return | exception.~n"),
    io:format("~n"),
  helped.


%%------------------------------------------------------------------------------
%% @doc
%% Start the server, and trace most important lbm_applications.
%% The trace is written to a file called "default-trace.log".
%% @end
%%------------------------------------------------------------------------------
-spec start() ->
                        {ok, pid()} | {error, term()}.
start() ->
    start([lbm_api,
           simple,
           erlce,
           lbm_lib,
           core,
           q931_lib], "default-trace.log").

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
    start(Applications, FileName, lbm_filter()).

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
%% Return a filter that is well suited for internal testing.
%% @end
%%------------------------------------------------------------------------------
-spec lbm_filter() ->
                        test().
lbm_filter() ->
    {orF, lbm_white_list(), {notF, lbm_black_list()}}.

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
                  [{module(), atom()}].
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
          applications   = []               :: [atom()],
          trace_active   = false            :: boolean(),
          trace_patterns = []               :: [{module(), '_', '_'}],
          filter         = allF             :: test(),
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
handle_info(Trace, State = #state{filter = Filter, io_device = IoDevice})
  when is_tuple(Trace) andalso element(1, Trace) =:= trace_ts ->
    if
        State#state.trace_active ->
            Msg = lists:flatten(
                         [M || T = {_, M} <- format(Trace),
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
-spec format(term()) ->
		    [{type(), string()}].
format({trace_ts, Pid, call, {M,F,A}, TimeStamp}) ->
    [{call,
      format(">>>", TimeStamp, Pid, {M, F, length(A)}, "applied to", A)}];

format({trace_ts, Pid, return_from, {M,F,A}, RV, TimeStamp}) ->
    [{return,
      format("<<<", TimeStamp, Pid, {M, F, A}, "returned", RV)}];

format({trace_ts, Pid, return_to, {M,F,A}, TimeStamp}) ->
    [{return,
      format("<<<", TimeStamp, Pid, {M,F,A}, "was returned to", "" )}];

format({trace_ts, Pid, exception_from, {M,F,A}, Exc, TimeStamp}) ->
    [{exception,
      format("*** EXCEPTION ***", TimeStamp, Pid,
             {M,F,A}, "threw", Exc)}];

format(_) ->
    [].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
format(Symbol, When, Pid, Func, Action, Arg) ->
    WhenStr = format_time(When),
    FuncStr = format_func(Func),
    lists:flatten(
      io_lib:format(
	"~s ~s ~-15w ~-40s ~15s: ~150p~n~n",
	[Symbol, WhenStr, Pid, FuncStr, Action, Arg])).

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
    Modules = get_modules(Applications),
    Patterns = get_trace_patterns(Modules),
    %% set the patterns
    [catch erlang:trace_pattern(MFA, ?MATCH_SPEC, []) || MFA <- Patterns],

    %% set the function trace
    catch erlang:trace(all, true, ?FLAGS),

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
    catch erlang:trace_pattern({'_', '_', '_'}, false, []),
    catch erlang:trace(all, false, [all]),
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
lbm_white_list() ->
    exception.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
lbm_black_list() ->
    {andF,
     {orF, call, return},
     {orF, [":handle_call",
            ":handle_cast",
            ":handle_info",
            ":handle_event",
            ":ref/2",
            "core_log_handler:",
            "core_media_id:",
            "core_descriptor:",
            "error_logger:",
            "lbm_object:"]}}.
