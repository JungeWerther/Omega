% Path of contain.py, the supervisor that runs each shell command and kills
% every process it leaves behind (including setsid/nohup/double-fork
% escapes). Recorded while this file is consulted, so it is found next to
% skills.pl wherever the repository lives.
:- dynamic omega_contain_script/1.
:- (   prolog_load_context(directory, Dir)
   ->  directory_file_path(Dir, 'contain.py', Script),
       retractall(omega_contain_script(_)),
       assertz(omega_contain_script(Script))
   ;   true
   ).

shell_timeout_seconds('5').

% The agent process becomes a subreaper on first use, and after every command
% kills whatever escaped contain.py (for example by killing it). Both go
% through janus; without it (plain swipl, tests) they are no-ops.
:- dynamic agent_contained/0.
contain_agent :-
    (   agent_contained
    ->  true
    ;   catch(py_call(contain:agent_init(), _), _, true),
        assertz(agent_contained)
    ).

sweep_agent :-
    catch(py_call(contain:agent_sweep(), _), E,
          ( E = error(existence_error(procedure, _), _)
          -> true
          ;  print_message(warning, E) )).

%Gets shell command return, plus the process if time limit is not met, returning timeout_error:
shell(Cmd, Out) :-
    (   omega_contain_script(Script), exists_file(Script)
    ->  true
    ;   throw(error(existence_error(file, 'src/contain.py'), shell/2))
    ),
    shell_timeout_seconds(Seconds),
    contain_agent,
    tmp_file_stream(text, TmpFile, TmpInit),
    close(TmpInit),
    open(TmpFile, write, TmpOut, [type(text)]),
    catch(
        setup_call_cleanup(
            process_create(
                path(python3),
                ['-I', Script, Seconds, '--', 'sh', '-c', Cmd],
                [ stdout(stream(TmpOut)),
                  stderr(stream(TmpOut)),
                  process(P)
                ]
            ),
            (
                process_wait(P, Status),
                close(TmpOut),
                read_file_to_string(TmpFile, Text, [])
            ),
            (
                catch(close(TmpOut), _, true),
                catch(delete_file(TmpFile), _, true),
                sweep_agent
            )
        ),
        E,
        (
            catch(close(TmpOut), _, true),
            catch(delete_file(TmpFile), _, true),
            throw(E)
        )
    ),
    ( Status = exit(125) -> Out = containment_error
    ; Status = exit(124) -> Out = timeout_error
    ; Status = exit(137) -> Out = timeout_error
    ; Status = killed(_) -> Out = timeout_error
    ; Out = Text
    ).


first_char(Str, C) :- sub_string(Str, 0, 1, _, C).

gc(true) :- garbage_collect,
            garbage_collect_atoms,
            trim_stacks.

read_file_tail(Path, MaxChars, Text) :-
    setup_call_cleanup(
        open(Path, read, In, [type(text), encoding(utf8)]),
        (
            seek(In, 0, eof, End),
            Start is max(0, End - MaxChars),
            seek(In, Start, bof, _),
            read_string(In, _, Text)
        ),
        close(In)
    ).
