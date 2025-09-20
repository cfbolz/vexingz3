# TODO List

## Next x86 Instructions to Implement

- [ ] **MUL (multiply)** - Implement multiplication operations (`Iop_Mul8/16/32/64`) with proper overflow handling

- [ ] **MOV with immediate values** - Support instructions like `mov rax, 0x1234` for constant loading

- [ ] **AND/OR/XOR** - Implement bitwise operations (`and rax, rbx`, `or rax, rbx`, `xor rax, rbx`)

- [ ] **CMP (compare)** - Add comparison instructions that set flags without storing results, requiring flag infrastructure implementation

## Implementation Notes

- Focus on test-driven development: write tests first, then implement
- Leverage existing dynamic dispatch architecture for new operations
- Ensure proper bit-width handling for all new operations
- Consider overflow and edge cases for each instruction type