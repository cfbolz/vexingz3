# VexingZ3

A VEX instruction interpreter for analyzing binary code.

## Overview

VexingZ3 provides an interpreter for VEX intermediate representation, allowing analysis of x86-64 assembly instructions through PyVEX. The interpreter supports various data sizes (8, 16, 32, 64-bit) and arithmetic operations.

## Features

- VEX IR interpretation for x86-64 instructions
- Support for multiple data sizes (8/16/32/64-bit)
- Arithmetic operations: ADD, SUB
- Proper register handling including sub-registers (al, ax, eax, rax)
- Extensible architecture for adding new operations

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
import pyvex
import archinfo
from vexingz3.interpreter import interpret

# Example: interpret "add rax, rbx"
ADD_INSTRUCTION = "4801d8"
inp = bytes.fromhex(ADD_INSTRUCTION)
irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

input_state = {'rax': 5, 'rbx': 3}
output_state = interpret(irsb, input_state)
print(output_state)  # {'rax': 8, 'rbx': 3}
```

## Testing

```bash
pytest vexingz3/test/
```

## Architecture

The interpreter uses dynamic method dispatch for operations:
- Binary operations: `_binop_Iop_<operation>`
- Unary operations: `_unop_Iop_<operation>`
- Automatic bitwidth masking for proper overflow behavior