# TODO List

## Next x86 Instructions to Implement

- [x] **MUL (multiply)** - Implement multiplication operations (`Iop_Mul8/16/32/64`) with proper overflow handling

- [x] **MOV with immediate values** - Support instructions like `mov rax, 0x1234` for constant loading

- [x] **AND/OR/XOR** - Implement bitwise operations (`and rax, rbx`, `or rax, rbx`, `xor rax, rbx`)

- [ ] **CMP (compare)** - Add comparison instructions that set flags without storing results, requiring flag infrastructure implementation

- [x] **SHL/SHR/SAR (shifts)** - Implement shift operations (`shl rax, 4`, `shr rax, cl`, `sar rax, 1`) for logical and arithmetic shifts

- [x] **ROL/ROR (rotates)** - Implement rotate operations (`rol rax, 4`, `ror eax, cl`) for left and right rotations

- [x] **DIV/IDIV (division)** - Implement division operations with proper remainder handling (`div rbx`, `idiv rbx`) for unsigned and signed division

## Implementation Notes

- Focus on test-driven development: write tests first, then implement
- Leverage existing dynamic dispatch architecture for new operations
- Ensure proper bit-width handling for all new operations
- Consider overflow and edge cases for each instruction type