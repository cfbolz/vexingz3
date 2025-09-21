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
  command

## Project Overview

This is a VEX (Valgrind Expression) project using PyVEX. The long-term goals of
the project are to write various tools to analyze VEX code.

## Key Dependencies

- **pyvex**: The main library for lifting binary code to VEX IR
- **archinfo**: Provides architecture information for different CPU architectures

## Virtual Environment

The project uses a symlinked virtual environment located at `../2025-09-20-angr-vibe/venv/`.
