# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## General style of working

- unit test every thing using pytest-style unit tests (please no unittest style tests).
- the humans working on this are all german. please communicate in a terse style. no exuberance. single line commit messages. maximum stars you would ever give to anything is four out of five. absolutely no jokes.
- please add comments very sparsely. don't explain *what* the code is doing, only why.
- try hard to work compact code, avoiding code duplication.
- if anything is ever unclear, please stop and ask questions. it's better to get the architecture right before starting to write a lot of code.
- errors should never pass silently. if you add code where you don't want to implement a case (yet), add an `assert False, "TODO"`

## Committing

- every logical chunk of work should be its own commit.
- before you commit, read through the diff and try to spot any code duplication
  that could be fixed with the introduction of helper functions that abstract
  common patterns
- there is a pre-commit hook in place that reformats code with black. it might
  be necessary to add those modified files again and re-do the git commit
  command. if that happens, you *must* not use `git commit --amend`, since that
  will modify some unrelated earlier commit.

## Project Overview

This is a VEX (Valgrind Expression) project using PyVEX. The long-term goals of
the project are to write various tools to analyze VEX code. Right now there are two tools

- A VEX interpreter in `vexingz3/interpreter.py` with tests in `vexingz3/test/test_interpreter.py`.
- A symbolic executor for that turns VEX code into Z3 SMT formulas. It re-uses
  the interpreter infrastructure by subclassing from it, overriding only select
  methods. It's in `vexingz3/vexz3.py`, with tests in `vexingz3/test/test_z3.py`.

## Key Dependencies

- **pyvex**: The main library for lifting binary code to VEX IR
- **archinfo**: Provides architecture information for different CPU architectures

## Virtual Environment

The project uses a symlinked virtual environment located at `venv/`.

## Notifications

Send desktop notifications using gdbus when:
- A task is finished (message: "finished: short description of what was done")
- Blocked and need to ask the user a question (message: short form of the question)

Command: `gdbus call --session --dest=org.freedesktop.Notifications --object-path=/org/freedesktop/Notifications --method=org.freedesktop.Notifications.Notify "" 1234 "" "MESSAGE" "Claude" '[]' '{"urgency": <1>}' 0`
