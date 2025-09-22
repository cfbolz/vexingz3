import struct

import archinfo
import pyvex

from vexingz3.interpreter import interpret


class Result:
    def __init__(self, registers, memory):
        self.registers = registers
        self.memory = memory
        # Allow direct access to registers for backward compatibility
        for reg, value in registers.items():
            setattr(self, reg, value)

    def __getitem__(self, key):
        return self.registers[key]


def float_to_int(float_val, precision="single"):
    """Convert float to integer representation."""
    if precision == "single":
        return int.from_bytes(struct.pack("<f", float_val), "little")
    else:  # double precision
        return int.from_bytes(struct.pack("<d", float_val), "little")


def int_to_float(int_val, precision="single"):
    """Convert integer to float representation."""
    if precision == "single":
        bytes_val = int_val.to_bytes(4, "little")
        return struct.unpack("<f", bytes_val)[0]
    else:  # double precision
        bytes_val = int_val.to_bytes(8, "little")
        return struct.unpack("<d", bytes_val)[0]


def pack_integers(integers, width):
    """Pack a list of integers into a single packed value.

    Args:
        integers: List of integers to pack (in little-endian order: [elem0, elem1, ...])
        width: Bit width of each element (8, 16, 32, or 64)

    Returns:
        Packed integer value
    """
    result = 0
    for i, value in enumerate(integers):
        mask = (1 << width) - 1
        masked_value = value & mask
        result |= masked_value << (i * width)
    return result


def unpack_integers(packed_value, width, count):
    """Unpack a packed integer value into a list of integers.

    Args:
        packed_value: The packed integer value
        width: Bit width of each element (8, 16, 32, or 64)
        count: Number of elements to extract

    Returns:
        List of integers in little-endian order: [elem0, elem1, ...]
    """
    mask = (1 << width) - 1
    result = []
    for i in range(count):
        element = (packed_value >> (i * width)) & mask
        result.append(element)
    return result


def run(instruction, memory=None, **initial_state):
    """Helper to run instruction with given register state and memory."""
    inp = bytes.fromhex(instruction)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    memory = memory if memory is not None else {}

    registers, final_memory = interpret(irsb, initial_state, memory)

    return Result(registers, final_memory)


def check_output(output_state, **expected):
    """Helper to check output state matches expected register values."""
    for reg, value in expected.items():
        assert output_state[reg] == value


def test_add_rax_rbx():
    output_state = run("4801d8", rax=5, rbx=3)  # add rax, rbx
    check_output(output_state, rax=8, rbx=3)


def test_add64_overflow():
    # 64-bit overflow: adding 1 to max uint64 should wrap to 0
    output_state = run("4801d8", rax=0xFFFFFFFFFFFFFFFF, rbx=1)
    check_output(output_state, rax=0)


def test_sub_rax_rbx():
    output_state = run("4829d8", rax=10, rbx=3)  # sub rax, rbx
    check_output(output_state, rax=7, rbx=3)


def test_add8_al_bl():
    # al=0x05, bl=0xb3 -> al=0xb8
    output_state = run("00d8", rax=0x12345678ABCDEF05, rbx=0x9876543210FEDCB3)
    check_output(output_state, rax=0x12345678ABCDEFB8, rbx=0x9876543210FEDCB3)


def test_add16_ax_bx():
    # ax=0x1234, bx=0x5678 -> ax=0x68ac
    output_state = run("6601d8", rax=0x12345678ABCD1234, rbx=0x9876543210FE5678)
    check_output(output_state, rax=0x12345678ABCD68AC, rbx=0x9876543210FE5678)


def test_add32_eax_ebx():
    # eax=0x12345678, ebx=0x9abcdef0 -> eax=0xacf13568 (32-bit zeros upper)
    output_state = run("01d8", rax=0xFEDCBA9812345678, rbx=0x123456789ABCDEF0)
    check_output(output_state, rax=0x00000000ACF13568, rbx=0x123456789ABCDEF0)


def test_sub8_al_bl():
    # al=0x80, bl=0x30 -> al=0x50
    output_state = run("28d8", rax=0x12345678ABCDEF80, rbx=0x9876543210FEDC30)
    check_output(output_state, rax=0x12345678ABCDEF50, rbx=0x9876543210FEDC30)


def test_sub16_ax_bx():
    # ax=0x8000, bx=0x3000 -> ax=0x5000
    output_state = run("6629d8", rax=0x12345678ABCD8000, rbx=0x9876543210FE3000)
    check_output(output_state, rax=0x12345678ABCD5000, rbx=0x9876543210FE3000)


def test_sub32_eax_ebx():
    # eax=0x80000000, ebx=0x30000000 -> eax=0x50000000 (32-bit zeros upper)
    output_state = run("29d8", rax=0xFEDCBA9880000000, rbx=0x12345678930000000)
    check_output(output_state, rax=0x0000000050000000, rbx=0x12345678930000000)


def test_and64_rax_rbx():
    output_state = run("4821d8", rax=0xFF00FF00FF00FF00, rbx=0xF0F0F0F0F0F0F0F0)
    check_output(output_state, rax=0xF000F000F000F000, rbx=0xF0F0F0F0F0F0F0F0)


def test_and8_al_bl():
    # al=0xFF, bl=0x0F -> al=0x0F
    output_state = run("20d8", rax=0x12345678ABCDEFFF, rbx=0x9876543210FEDC0F)
    check_output(output_state, rax=0x12345678ABCDEF0F, rbx=0x9876543210FEDC0F)


def test_or64_rax_rbx():
    output_state = run("4809d8", rax=0xFF00FF00FF00FF00, rbx=0x0F0F0F0F0F0F0F0F)
    check_output(output_state, rax=0xFF0FFF0FFF0FFF0F, rbx=0x0F0F0F0F0F0F0F0F)


def test_xor64_rax_rbx():
    output_state = run("4831d8", rax=0xFF00FF00FF00FF00, rbx=0xF0F0F0F0F0F0F0F0)
    check_output(output_state, rax=0x0FF00FF00FF00FF0, rbx=0xF0F0F0F0F0F0F0F0)


def test_mov_immediate_rax():
    # mov rax, 0x1234
    output_state = run("48c7c034120000", rax=0xDEADBEEF)
    check_output(output_state, rax=0x1234)


def test_mov_immediate_rbx():
    # mov rbx, 0x5678
    output_state = run("48c7c378560000", rbx=0xCAFEBABE)
    check_output(output_state, rbx=0x5678)


def test_mov_immediate_zero():
    # mov rax, 0x0
    output_state = run("48c7c000000000", rax=0xFFFFFFFFFFFFFFFF)
    check_output(output_state, rax=0x0)


def test_imul64_rax_rbx():
    # imul rax, rbx (signed multiply)
    output_state = run("480fafc3", rax=6, rbx=7)
    check_output(output_state, rax=42, rbx=7)


def test_mul64_overflow():
    # imul rax, rbx - Test 64-bit multiply overflow wrapping
    output_state = run("480fafc3", rax=0xFFFFFFFFFFFFFFFF, rbx=2)
    check_output(output_state, rax=0xFFFFFFFFFFFFFFFE, rbx=2)


def test_mul32_unsigned():
    # mul ebx (unsigned multiply eax * ebx -> edx:eax)
    output_state = run("f7e3", rax=0x12345678, rbx=0x9ABCDEF0)
    # Result should be in edx:eax (high:low parts of 64-bit result)
    expected_result = (0x12345678 & 0xFFFFFFFF) * (0x9ABCDEF0 & 0xFFFFFFFF)
    expected_low = expected_result & 0xFFFFFFFF
    expected_high = (expected_result >> 32) & 0xFFFFFFFF
    check_output(output_state, rax=expected_low, rdx=expected_high)


def test_mul32_maximum_values():
    # Test multiplication of maximum 32-bit values
    output_state = run("f7e3", rax=0xFFFFFFFF, rbx=0xFFFFFFFF)
    # 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
    check_output(output_state, rax=0x00000001, rdx=0xFFFFFFFE)


def test_mul8_al_bl():
    # mul bl (8-bit multiply al * bl -> ax)
    output_state = run("f6e3", rax=0x12345678ABCDEF05, rbx=0x9876543210FEDC0A)
    # al=0x05, bl=0x0A -> ax=0x0032 (5 * 10 = 50 = 0x32)
    check_output(output_state, rax=0x12345678ABCD0032, rbx=0x9876543210FEDC0A)


def test_mul16_ax_bx():
    # mul bx (16-bit multiply ax * bx -> dx:ax)
    output_state = run("66f7e3", rax=0x12345678ABCD1234, rbx=0x9876543210FE5678)
    # ax=0x1234, bx=0x5678 -> result=0x06260060, dx=0x0626, ax=0x0060
    expected_result = 0x1234 * 0x5678
    expected_low = expected_result & 0xFFFF
    expected_high = (expected_result >> 16) & 0xFFFF
    check_output(output_state, rax=0x12345678ABCD0000 | expected_low, rdx=expected_high)


def test_mul64_unsigned():
    # mul rbx (64-bit unsigned multiply rax * rbx -> rdx:rax)
    output_state = run("48f7e3", rax=0x123456789ABCDEF0, rbx=0x0000000000000002)
    # Simple case: multiply by 2
    expected_result = 0x123456789ABCDEF0 * 2
    expected_low = expected_result & 0xFFFFFFFFFFFFFFFF
    expected_high = (expected_result >> 64) & 0xFFFFFFFFFFFFFFFF
    check_output(output_state, rax=expected_low, rdx=expected_high)


def test_mul64_unsigned_overflow():
    # mul rbx (64-bit multiply with significant upper bits)
    output_state = run("48f7e3", rax=0xFFFFFFFFFFFFFFFF, rbx=0xFFFFFFFFFFFFFFFF)
    # 0xFFFFFFFFFFFFFFFF * 0xFFFFFFFFFFFFFFFF = 0xFFFFFFFFFFFFFFFE0000000000000001
    check_output(output_state, rax=0x0000000000000001, rdx=0xFFFFFFFFFFFFFFFE)


def test_imul64_signed():
    # imul rbx (64-bit signed multiply rax * rbx -> rdx:rax)
    output_state = run("48f7eb", rax=0xFFFFFFFFFFFFFFFF, rbx=0x0000000000000002)
    # -1 * 2 = -2 (0xFFFFFFFFFFFFFFFE in two's complement)
    # In 128-bit: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    check_output(output_state, rax=0xFFFFFFFFFFFFFFFE, rdx=0xFFFFFFFFFFFFFFFF)


def test_imul8_signed():
    # imul bl (8-bit signed multiply al * bl -> ax)
    output_state = run("f6eb", rax=0x12345678ABCDEFFF, rbx=0x9876543210FEDC02)
    # al=0xFF (-1), bl=0x02 (2) -> ax=0xFFFE (-2 in 16-bit two's complement)
    check_output(output_state, rax=0x12345678ABCDFFFE, rbx=0x9876543210FEDC02)


def test_imul16_signed():
    # imul bx (16-bit signed multiply ax * bx -> dx:ax)
    output_state = run("66f7eb", rax=0x12345678ABCDFFFF, rbx=0x9876543210FE0002)
    # ax=0xFFFF (-1), bx=0x0002 (2) -> result=0xFFFFFFFE (-2 in 32-bit)
    # dx=0xFFFF, ax=0xFFFE
    check_output(output_state, rax=0x12345678ABCDFFFE, rdx=0xFFFF)


def test_imul32_signed():
    # imul ebx (32-bit signed multiply eax * ebx -> rdx:eax)
    output_state = run("f7eb", rax=0xFEDCBA98FFFFFFFF, rbx=0x1234567800000002)
    # eax=0xFFFFFFFF (-1), ebx=0x00000002 (2) -> result=0xFFFFFFFFFFFFFFFE (-2)
    # rdx=0xFFFFFFFF, eax=0xFFFFFFFE
    check_output(output_state, rax=0x00000000FFFFFFFE, rdx=0xFFFFFFFF)


def test_lea_rax_plus_constant():
    # lea rbx, [rax+8]
    output_state = run("488d5808", rax=0x1000, rbx=0xDEADBEEF)
    check_output(output_state, rax=0x1000, rbx=0x1008)


def test_lea_rax_plus_rbx():
    # lea rbx, [rax+rbx]
    output_state = run("488d1c18", rax=0x1000, rbx=0x500)
    check_output(output_state, rax=0x1000, rbx=0x1500)


def test_lea_rax_plus_rbx_plus_constant():
    # lea rbx, [rax+rbx+8]
    output_state = run("488d5c1808", rax=0x1000, rbx=0x500)
    check_output(output_state, rax=0x1000, rbx=0x1508)


def test_lea_with_scale_factor():
    # lea rbx, [rax+rax*2]  (rax + rax*2 = rax*3)
    output_state = run("488d1c40", rax=0x100, rbx=0xDEADBEEF)
    check_output(output_state, rax=0x100, rbx=0x300)


def test_shl64_invalid_shift_count():
    # Test that invalid shift counts are caught by the assert
    import pytest

    from vexingz3.interpreter import State

    state = State()

    # Test invalid shift count > 63
    with pytest.raises(AssertionError, match="Shift count 64 out of range"):
        state._binop_Iop_Shl64(None, 0x100, 64)

    # Test negative shift count
    with pytest.raises(AssertionError, match="Shift count -1 out of range"):
        state._binop_Iop_Shl64(None, 0x100, -1)


def test_shl64_basic():
    # shl rax, 4
    output_state = run("48c1e004", rax=0x1234567890ABCDEF)
    check_output(output_state, rax=0x234567890ABCDEF0)


def test_shl32_basic():
    # shl eax, 4
    output_state = run("c1e004", rax=0xFEDCBA9812345678)
    check_output(output_state, rax=0x0000000023456780)


def test_shl16_basic():
    # shl ax, 4
    output_state = run("66c1e004", rax=0x1234567890AB1234)
    check_output(output_state, rax=0x1234567890AB2340)


def test_shl8_basic():
    # shl al, 4
    output_state = run("c0e004", rax=0x123456789ABCDE12)
    check_output(output_state, rax=0x123456789ABCDE20)


def test_shr64_basic():
    # shr rax, 4
    output_state = run("48c1e804", rax=0x1234567890ABCDEF)
    check_output(output_state, rax=0x01234567890ABCDE)


def test_shr32_basic():
    # shr eax, 4
    output_state = run("c1e804", rax=0xFEDCBA9812345678)
    check_output(output_state, rax=0x0000000001234567)


def test_shr16_basic():
    # shr ax, 4
    output_state = run("66c1e804", rax=0x1234567890AB1234)
    check_output(output_state, rax=0x1234567890AB0123)


def test_shr8_basic():
    # shr al, 4
    output_state = run("c0e804", rax=0x123456789ABCDE12)
    check_output(output_state, rax=0x123456789ABCDE01)


def test_sar64_positive():
    # sar rax, 4 (positive number)
    output_state = run("48c1f804", rax=0x1234567890ABCDEF)
    check_output(output_state, rax=0x01234567890ABCDE)


def test_sar64_negative():
    # sar rax, 4 (negative number - sign extension)
    output_state = run("48c1f804", rax=0xFEDCBA9876543210)
    check_output(output_state, rax=0xFFEDCBA987654321)


def test_sar32_negative():
    # sar eax, 4 (negative 32-bit number)
    output_state = run("c1f804", rax=0x12345678FEDCBA98)
    check_output(output_state, rax=0x00000000FFEDCBA9)


def test_sar16_negative():
    # sar ax, 4 (negative 16-bit number)
    output_state = run("66c1f804", rax=0x123456789ABCFED0)
    check_output(output_state, rax=0x123456789ABCFFED)


def test_sar8_negative():
    # sar al, 4 (negative 8-bit number)
    output_state = run("c0f804", rax=0x123456789ABCDEF0)
    check_output(output_state, rax=0x123456789ABCDEFF)


def test_shl64_variable():
    # shl rax, cl
    output_state = run("48d3e0", rax=0x1234567890ABCDEF, rcx=0x04)
    check_output(output_state, rax=0x234567890ABCDEF0, rcx=0x04)


def test_shl32_variable():
    # shl eax, cl
    output_state = run("d3e0", rax=0xFEDCBA9812345678, rcx=0x04)
    check_output(output_state, rax=0x0000000023456780, rcx=0x04)


def test_shl16_variable():
    # shl ax, cl
    output_state = run("66d3e0", rax=0x1234567890AB1234, rcx=0x04)
    check_output(output_state, rax=0x1234567890AB2340, rcx=0x04)


def test_shr64_variable():
    # shr rax, cl
    output_state = run("48d3e8", rax=0x1234567890ABCDEF, rcx=0x04)
    check_output(output_state, rax=0x01234567890ABCDE, rcx=0x04)


def test_sar64_variable_negative():
    # sar rax, cl (negative number)
    output_state = run("48d3f8", rax=0xFEDCBA9876543210, rcx=0x04)
    check_output(output_state, rax=0xFFEDCBA987654321, rcx=0x04)


def test_shl64_variable_large_shift():
    # shl rax, cl (test that shift count is properly masked)
    output_state = run("48d3e0", rax=0x1234567890ABCDEF, rcx=0x44)  # 0x44 & 0x3f = 4
    check_output(output_state, rax=0x234567890ABCDEF0, rcx=0x44)


def test_rol64_basic():
    # rol rax, 4
    output_state = run("48c1c004", rax=0x1234567890ABCDEF)
    # Rotate left 4: 0x1234567890ABCDEF -> 0x234567890ABCDEF1
    check_output(output_state, rax=0x234567890ABCDEF1)


def test_rol32_basic():
    # rol eax, 4
    output_state = run("c1c004", rax=0xFEDCBA9812345678)
    # Rotate left 4: 0x12345678 -> 0x23456781
    check_output(output_state, rax=0x0000000023456781)


def test_rol16_basic():
    # rol ax, 4
    output_state = run("66c1c004", rax=0x123456789ABC1234)
    # Rotate left 4: 0x1234 -> 0x2341
    check_output(output_state, rax=0x123456789ABC2341)


def test_rol8_basic():
    # rol al, 4
    output_state = run("c0c004", rax=0x123456789ABCDE12)
    # Rotate left 4: 0x12 -> 0x21
    check_output(output_state, rax=0x123456789ABCDE21)


def test_ror64_basic():
    # ror rax, 4
    output_state = run("48c1c804", rax=0x1234567890ABCDEF)
    # Rotate right 4: 0x1234567890ABCDEF -> 0xF1234567890ABCDE
    check_output(output_state, rax=0xF1234567890ABCDE)


def test_ror32_basic():
    # ror eax, 4
    output_state = run("c1c804", rax=0xFEDCBA9812345678)
    # Rotate right 4: 0x12345678 -> 0x81234567
    check_output(output_state, rax=0x0000000081234567)


def test_ror16_basic():
    # ror ax, 4
    output_state = run("66c1c804", rax=0x123456789ABC1234)
    # Rotate right 4: 0x1234 -> 0x4123
    check_output(output_state, rax=0x123456789ABC4123)


def test_ror8_basic():
    # ror al, 4
    output_state = run("c0c804", rax=0x123456789ABCDE12)
    # Rotate right 4: 0x12 -> 0x21
    check_output(output_state, rax=0x123456789ABCDE21)


def test_rol64_variable():
    # rol rax, cl
    output_state = run("48d3c0", rax=0x1234567890ABCDEF, rcx=0x04)
    # Same as rol rax, 4
    check_output(output_state, rax=0x234567890ABCDEF1, rcx=0x04)


def test_ror64_variable():
    # ror rax, cl
    output_state = run("48d3c8", rax=0x1234567890ABCDEF, rcx=0x04)
    # Same as ror rax, 4
    check_output(output_state, rax=0xF1234567890ABCDE, rcx=0x04)


def test_div64_basic():
    # div rbx (unsigned 64-bit division)
    # rax = 100, rdx = 0, rbx = 10 -> rax = 10, rdx = 0
    output_state = run("48f7f3", rax=100, rdx=0, rbx=10)
    check_output(output_state, rax=10, rdx=0, rbx=10)


def test_div64_with_remainder():
    # div rbx (unsigned 64-bit division)
    # rax = 107, rdx = 0, rbx = 10 -> rax = 10, rdx = 7
    output_state = run("48f7f3", rax=107, rdx=0, rbx=10)
    check_output(output_state, rax=10, rdx=7, rbx=10)


def test_div32_basic():
    # div ebx (unsigned 32-bit division)
    # eax = 100, edx = 0, ebx = 10 -> eax = 10, edx = 0
    output_state = run("f7f3", rax=100, rdx=0, rbx=10)
    check_output(output_state, rax=10, rdx=0, rbx=10)


def test_idiv64_positive():
    # idiv rbx (signed 64-bit division)
    # rax = 100, rdx = 0, rbx = 10 -> rax = 10, rdx = 0
    output_state = run("48f7fb", rax=100, rdx=0, rbx=10)
    check_output(output_state, rax=10, rdx=0, rbx=10)


def test_idiv64_negative_dividend():
    # idiv rbx (signed 64-bit division)
    # rax = -100, rdx = -1, rbx = 10 -> rax = -10, rdx = 0
    output_state = run("48f7fb", rax=0xFFFFFFFFFFFFFF9C, rdx=0xFFFFFFFFFFFFFFFF, rbx=10)
    check_output(output_state, rax=0xFFFFFFFFFFFFFFF6, rdx=0, rbx=10)


def test_idiv64_negative_divisor():
    # idiv rbx (signed 64-bit division)
    # rax = 100, rdx = 0, rbx = -10 -> rax = -10, rdx = 0
    output_state = run("48f7fb", rax=100, rdx=0, rbx=0xFFFFFFFFFFFFFFF6)
    check_output(output_state, rax=0xFFFFFFFFFFFFFFF6, rdx=0, rbx=0xFFFFFFFFFFFFFFF6)


def test_idiv64_c_style_truncation():
    # idiv rbx (signed 64-bit division)
    # Test C-style truncation: -7 / 3 = -2 remainder -1 (C-style)
    # Python would give: -7 // 3 = -3 remainder 2
    # rax = -7, rdx = -1, rbx = 3 -> rax = -2, rdx = -1
    output_state = run("48f7fb", rax=0xFFFFFFFFFFFFFFF9, rdx=0xFFFFFFFFFFFFFFFF, rbx=3)
    check_output(output_state, rax=0xFFFFFFFFFFFFFFFE, rdx=0xFFFFFFFFFFFFFFFF, rbx=3)


def test_memory_load_64bit():
    # mov rax, [rbx] - load 64-bit value from memory
    # Set up memory at address 0x1000 with value 0x123456789ABCDEF0
    memory = {}
    for i, byte_val in enumerate([0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]):
        memory[0x1000 + i] = byte_val

    output_state = run("488b03", rbx=0x1000, memory=memory)
    check_output(output_state, rax=0x123456789ABCDEF0, rbx=0x1000)


def test_memory_load_32bit():
    # mov eax, [rbx] - load 32-bit value from memory
    # Set up memory at address 0x1000 with value 0x12345678
    memory = {}
    for i, byte_val in enumerate([0x78, 0x56, 0x34, 0x12]):
        memory[0x1000 + i] = byte_val

    output_state = run("8b03", rbx=0x1000, memory=memory)
    check_output(output_state, rax=0x12345678, rbx=0x1000)


def test_memory_load_16bit():
    # mov ax, [rbx] - load 16-bit value from memory
    # Set up memory at address 0x1000 with value 0x1234
    memory = {}
    for i, byte_val in enumerate([0x34, 0x12]):
        memory[0x1000 + i] = byte_val

    output_state = run("668b03", rax=0xFFFFFFFFFFFFFFFF, rbx=0x1000, memory=memory)
    check_output(output_state, rax=0xFFFFFFFFFFFF1234, rbx=0x1000)


def test_memory_load_8bit():
    # mov al, [rbx] - load 8-bit value from memory
    # Set up memory at address 0x1000 with value 0x42
    memory = {0x1000: 0x42}

    output_state = run("8a03", rax=0xFFFFFFFFFFFFFFFF, rbx=0x1000, memory=memory)
    check_output(output_state, rax=0xFFFFFFFFFFFFFF42, rbx=0x1000)


def test_memory_store_64bit():
    # mov [rbx], rax - store 64-bit value to memory
    output_state = run("488903", rax=0x123456789ABCDEF0, rbx=0x1000)
    check_output(output_state, rax=0x123456789ABCDEF0, rbx=0x1000)

    # Check memory was written correctly (little-endian)
    expected_bytes = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
    for i, expected_byte in enumerate(expected_bytes):
        assert output_state.memory[0x1000 + i] == expected_byte


def test_memory_store_32bit():
    # mov [rbx], eax - store 32-bit value to memory
    output_state = run("8903", rax=0x12345678, rbx=0x1000)
    check_output(output_state, rax=0x12345678, rbx=0x1000)

    # Check memory was written correctly (little-endian)
    expected_bytes = [0x78, 0x56, 0x34, 0x12]
    for i, expected_byte in enumerate(expected_bytes):
        assert output_state.memory[0x1000 + i] == expected_byte


def test_memory_store_16bit():
    # mov [rbx], ax - store 16-bit value to memory
    output_state = run("668903", rax=0x1234, rbx=0x1000)
    check_output(output_state, rax=0x1234, rbx=0x1000)

    # Check memory was written correctly (little-endian)
    expected_bytes = [0x34, 0x12]
    for i, expected_byte in enumerate(expected_bytes):
        assert output_state.memory[0x1000 + i] == expected_byte


def test_memory_store_8bit():
    # mov [rbx], al - store 8-bit value to memory
    output_state = run("8803", rax=0x42, rbx=0x1000)
    check_output(output_state, rax=0x42, rbx=0x1000)

    # Check memory was written correctly
    assert output_state.memory[0x1000] == 0x42


def test_memory_load_store_roundtrip():
    # Test that we can store a value and load it back
    # First store: mov [rbx], rax
    store_result = run("488903", rax=0x123456789ABCDEF0, rbx=0x2000)

    # Then load: mov rcx, [rbx]
    load_result = run("488b0b", rbx=0x2000, memory=store_result.memory)
    check_output(load_result, rcx=0x123456789ABCDEF0, rbx=0x2000)


def test_push_rax():
    # push rax - pushes 64-bit value onto stack
    output_state = run("50", rax=0x123456789ABCDEF0, rsp=0x1000)

    # RSP should be decremented by 8 bytes
    check_output(output_state, rax=0x123456789ABCDEF0, rsp=0x0FF8)

    # Check memory at new RSP contains the pushed value (little-endian)
    expected_bytes = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
    for i, expected_byte in enumerate(expected_bytes):
        assert output_state.memory[0x0FF8 + i] == expected_byte


def test_pop_rax():
    # pop rax - pops 64-bit value from stack
    # Set up stack with value 0x123456789ABCDEF0
    memory = {}
    value_bytes = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
    for i, byte_val in enumerate(value_bytes):
        memory[0x0FF8 + i] = byte_val

    output_state = run("58", rsp=0x0FF8, memory=memory)

    # RSP should be incremented by 8 bytes, RAX should contain popped value
    check_output(output_state, rax=0x123456789ABCDEF0, rsp=0x1000)


def test_push_ax():
    # push ax - pushes 16-bit value onto stack
    output_state = run("6650", rax=0x1234, rsp=0x1000)

    # RSP should be decremented by 2 bytes
    check_output(output_state, rax=0x1234, rsp=0x0FFE)

    # Check memory at new RSP contains the pushed value (little-endian)
    expected_bytes = [0x34, 0x12]
    for i, expected_byte in enumerate(expected_bytes):
        assert output_state.memory[0x0FFE + i] == expected_byte


def test_pop_ax():
    # pop ax - pops 16-bit value from stack
    # Set up stack with value 0x1234
    memory = {0x0FFE: 0x34, 0x0FFF: 0x12}

    output_state = run("6658", rax=0xFFFFFFFFFFFFFFFF, rsp=0x0FFE, memory=memory)

    # RSP should be incremented by 2 bytes, AX should contain popped value
    check_output(output_state, rax=0xFFFFFFFFFFFF1234, rsp=0x1000)


def test_push_pop_roundtrip():
    # Test that we can push a value and pop it back
    # First push: push rax
    push_result = run("50", rax=0xDEADBEEFCAFEBABE, rsp=0x2000)

    # Then pop into a different register: pop rbx
    pop_result = run("5b", rsp=push_result.rsp, memory=push_result.memory)

    # Should get original value back and RSP should return to original value
    check_output(pop_result, rbx=0xDEADBEEFCAFEBABE, rsp=0x2000)


def test_stack_multiple_operations():
    # Test LIFO behavior with multiple pushes and pops
    initial_rsp = 0x3000

    # Push three values: 0x1111, 0x2222, 0x3333
    # push rax (0x1111)
    result1 = run("50", rax=0x1111, rsp=initial_rsp)
    assert result1.rsp == initial_rsp - 8

    # push rbx (0x2222)
    result2 = run("53", rbx=0x2222, rsp=result1.rsp, memory=result1.memory)
    assert result2.rsp == initial_rsp - 16

    # push rcx (0x3333)
    result3 = run("51", rcx=0x3333, rsp=result2.rsp, memory=result2.memory)
    assert result3.rsp == initial_rsp - 24

    # Now pop them back in reverse order (LIFO)
    # pop rdx (should get 0x3333)
    result4 = run("5a", rsp=result3.rsp, memory=result3.memory)
    check_output(result4, rdx=0x3333, rsp=initial_rsp - 16)

    # pop rsi (should get 0x2222)
    result5 = run("5e", rsp=result4.rsp, memory=result4.memory)
    check_output(result5, rsi=0x2222, rsp=initial_rsp - 8)

    # pop rdi (should get 0x1111)
    result6 = run("5f", rsp=result5.rsp, memory=result5.memory)
    check_output(result6, rdi=0x1111, rsp=initial_rsp)


def test_neg_rax():
    # neg rax - two's complement negation of 64-bit value
    output_state = run("48f7d8", rax=0x123456789ABCDEF0)
    # -0x123456789ABCDEF0 = 0xEDCBA9876543210F + 1 = 0xEDCBA98765432110
    check_output(output_state, rax=0xEDCBA98765432110)


def test_neg_eax():
    # neg eax - two's complement negation of 32-bit value
    output_state = run("f7d8", rax=0x12345678)
    # -0x12345678 = 0xEDCBA987 + 1 = 0xEDCBA988 (32-bit)
    check_output(output_state, rax=0xEDCBA988)


def test_neg_zero():
    # neg rax with zero - should remain zero
    output_state = run("48f7d8", rax=0x0)
    check_output(output_state, rax=0x0)


def test_not_rax():
    # not rax - bitwise complement of 64-bit value
    output_state = run("48f7d0", rax=0x123456789ABCDEF0)
    # ~0x123456789ABCDEF0 = 0xEDCBA9876543210F
    check_output(output_state, rax=0xEDCBA9876543210F)


def test_not_eax():
    # not eax - bitwise complement of 32-bit value
    output_state = run("f7d0", rax=0x12345678)
    # ~0x12345678 = 0xEDCBA987 (32-bit), zero-extended to 64-bit
    check_output(output_state, rax=0xEDCBA987)


def test_not_all_ones():
    # not rax with all ones - should become zero
    output_state = run("48f7d0", rax=0xFFFFFFFFFFFFFFFF)
    check_output(output_state, rax=0x0)


def test_inc_rax():
    # inc rax - increment 64-bit value
    output_state = run("48ffc0", rax=0x123456789ABCDEF0)
    check_output(output_state, rax=0x123456789ABCDEF1)


def test_inc_eax():
    # inc eax - increment 32-bit value
    output_state = run("ffc0", rax=0x12345678)
    check_output(output_state, rax=0x12345679)


def test_inc_overflow():
    # inc rax with max value - should overflow to zero
    output_state = run("48ffc0", rax=0xFFFFFFFFFFFFFFFF)
    check_output(output_state, rax=0x0)


def test_dec_rax():
    # dec rax - decrement 64-bit value
    output_state = run("48ffc8", rax=0x123456789ABCDEF1)
    check_output(output_state, rax=0x123456789ABCDEF0)


def test_dec_eax():
    # dec eax - decrement 32-bit value
    output_state = run("ffc8", rax=0x12345679)
    check_output(output_state, rax=0x12345678)


def test_dec_underflow():
    # dec rax with zero - should underflow to max value
    output_state = run("48ffc8", rax=0x0)
    check_output(output_state, rax=0xFFFFFFFFFFFFFFFF)


def test_cmp_cmovg_greater():
    # Test CMP + CMOVG when first operand is greater
    # cmp rax, rbx + cmovg rcx, rdx
    # When rax > rbx, should move rdx to rcx
    output_state = run("4839d8480f4fca", rax=10, rbx=5, rcx=0x1111, rdx=0x2222)
    check_output(output_state, rax=10, rbx=5, rcx=0x2222, rdx=0x2222)


def test_cmp_cmovg_not_greater():
    # Test CMP + CMOVG when first operand is not greater
    # cmp rax, rbx + cmovg rcx, rdx
    # When rax <= rbx, should keep rcx unchanged
    output_state = run("4839d8480f4fca", rax=5, rbx=10, rcx=0x1111, rdx=0x2222)
    check_output(output_state, rax=5, rbx=10, rcx=0x1111, rdx=0x2222)


def test_cmp_cmovg_equal():
    # Test CMP + CMOVG when operands are equal
    # cmp rax, rbx + cmovg rcx, rdx
    # When rax == rbx, should keep rcx unchanged (not greater)
    output_state = run("4839d8480f4fca", rax=5, rbx=5, rcx=0x1111, rdx=0x2222)
    check_output(output_state, rax=5, rbx=5, rcx=0x1111, rdx=0x2222)


def test_test_rax_rbx():
    # test rax, rbx - bitwise AND for flag setting, don't store result
    # Should not modify any registers, just set flags
    output_state = run("4885d8", rax=0xFF00, rbx=0x00FF)
    check_output(output_state, rax=0xFF00, rbx=0x00FF)


def test_test_zero_result():
    # test rax, rbx when AND result is zero (common zero flag test)
    output_state = run("4885d8", rax=0xF0F0, rbx=0x0F0F)
    check_output(output_state, rax=0xF0F0, rbx=0x0F0F)


def test_test_nonzero_result():
    # test rax, rbx when AND result is non-zero
    output_state = run("4885d8", rax=0xFFFF, rbx=0xFF00)
    check_output(output_state, rax=0xFFFF, rbx=0xFF00)


def test_movaps_xmm0_xmm1():
    # movaps xmm0, xmm1 - move 128-bit aligned packed single precision
    # Should copy 128-bit value from xmm1 to xmm0 (mapped as ymm registers)
    output_state = run("0f28c1", ymm1=0x12345678ABCDEF0011223344AABBCCDD)
    check_output(
        output_state,
        ymm0=0x12345678ABCDEF0011223344AABBCCDD,
        ymm1=0x12345678ABCDEF0011223344AABBCCDD,
    )


def test_addps_xmm0_xmm1():
    # addps xmm0, xmm1 - add 4 packed 32-bit values (mapped as ymm registers)
    # For simplicity, treating as integer addition of 32-bit chunks
    # xmm0 = [0x01, 0x02, 0x03, 0x04] + xmm1 = [0x10, 0x20, 0x30, 0x40]
    # Expected result: [0x11, 0x22, 0x33, 0x44]
    output_state = run(
        "0f58c1",
        ymm0=0x04000000030000000200000001000000,  # [4,3,2,1] in little-endian
        ymm1=0x40000000300000002000000010000000,
    )  # [64,48,32,16] in little-endian
    # Result should be [68,51,34,17] = 0x44000000330000002200000011000000
    check_output(output_state, ymm0=0x44000000330000002200000011000000)


def test_addsd_double_precision():
    # addsd xmm0, xmm1 - double precision scalar add (3.14 + 2.71 = 5.85)
    val1 = 3.14
    val2 = 2.71
    val1_int = float_to_int(val1, "double")
    val2_int = float_to_int(val2, "double")
    expected = val1 + val2
    expected_int = float_to_int(expected, "double")

    output_state = run("f20f58c1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_subsd_double_precision():
    # subsd xmm0, xmm1 - double precision scalar subtract (5.5 - 2.25 = 3.25)
    val1 = 5.5
    val2 = 2.25
    val1_int = float_to_int(val1, "double")
    val2_int = float_to_int(val2, "double")
    expected = val1 - val2
    expected_int = float_to_int(expected, "double")

    output_state = run("f20f5cc1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_mulsd_double_precision():
    # mulsd xmm0, xmm1 - double precision scalar multiply (4.0 * 1.5 = 6.0)
    val1 = 4.0
    val2 = 1.5
    val1_int = float_to_int(val1, "double")
    val2_int = float_to_int(val2, "double")
    expected = val1 * val2
    expected_int = float_to_int(expected, "double")

    output_state = run("f20f59c1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_divsd_double_precision():
    # divsd xmm0, xmm1 - double precision scalar divide (8.0 / 2.0 = 4.0)
    val1 = 8.0
    val2 = 2.0
    val1_int = float_to_int(val1, "double")
    val2_int = float_to_int(val2, "double")
    expected = val1 / val2
    expected_int = float_to_int(expected, "double")

    output_state = run("f20f5ec1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_addss_single_precision():
    # addss xmm0, xmm1 - single precision scalar add (2.5 + 1.5 = 4.0)
    val1 = 2.5
    val2 = 1.5
    val1_int = float_to_int(val1, "single")
    val2_int = float_to_int(val2, "single")
    expected = val1 + val2
    expected_int = float_to_int(expected, "single")

    output_state = run("f30f58c1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_subss_single_precision():
    # subss xmm0, xmm1 - single precision scalar subtract (7.0 - 3.0 = 4.0)
    val1 = 7.0
    val2 = 3.0
    val1_int = float_to_int(val1, "single")
    val2_int = float_to_int(val2, "single")
    expected = val1 - val2
    expected_int = float_to_int(expected, "single")

    output_state = run("f30f5cc1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_mulss_single_precision():
    # mulss xmm0, xmm1 - single precision scalar multiply (3.0 * 2.0 = 6.0)
    val1 = 3.0
    val2 = 2.0
    val1_int = float_to_int(val1, "single")
    val2_int = float_to_int(val2, "single")
    expected = val1 * val2
    expected_int = float_to_int(expected, "single")

    output_state = run("f30f59c1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_divss_single_precision():
    # divss xmm0, xmm1 - single precision scalar divide (12.0 / 4.0 = 3.0)
    val1 = 12.0
    val2 = 4.0
    val1_int = float_to_int(val1, "single")
    val2_int = float_to_int(val2, "single")
    expected = val1 / val2
    expected_int = float_to_int(expected, "single")

    output_state = run("f30f5ec1", ymm0=val1_int, ymm1=val2_int)
    check_output(output_state, ymm0=expected_int)


def test_pand_128bit():
    # pand xmm0, xmm1 - 128-bit bitwise AND
    val1 = 0x12345678ABCDEF9876543210FEDCBA98
    val2 = 0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0
    expected = val1 & val2

    output_state = run("660fdbc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_por_128bit():
    # por xmm0, xmm1 - 128-bit bitwise OR
    val1 = 0x12345678ABCDEF9876543210FEDCBA98
    val2 = 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
    expected = val1 | val2

    output_state = run("660febc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_pxor_128bit():
    # pxor xmm0, xmm1 - 128-bit bitwise XOR
    val1 = 0x12345678ABCDEF9876543210FEDCBA98
    val2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    expected = val1 ^ val2

    output_state = run("660fefc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_pandn_128bit():
    # pandn xmm0, xmm1 - 128-bit AND NOT (NOT xmm0, then AND with xmm1)
    val1 = 0x12345678ABCDEF9876543210FEDCBA98
    val2 = 0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0
    # pandn does: (~val1) & val2
    expected = (~val1) & val2 & ((1 << 128) - 1)

    output_state = run("660fdfc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_vpand_256bit():
    # vpand ymm0, ymm1, ymm2 - 256-bit bitwise AND
    val1 = 0x12345678ABCDEF9876543210FEDCBA9887654321FEDCBA9876543210ABCDEF98
    val2 = 0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0
    expected = val1 & val2

    output_state = run("c5f5dbc2", ymm1=val1, ymm2=val2)
    check_output(output_state, ymm0=expected)


def test_vpor_256bit():
    # vpor ymm0, ymm1, ymm2 - 256-bit bitwise OR
    val1 = 0x12345678ABCDEF9876543210FEDCBA9887654321FEDCBA9876543210ABCDEF98
    val2 = 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
    expected = val1 | val2

    output_state = run("c5f5ebc2", ymm1=val1, ymm2=val2)
    check_output(output_state, ymm0=expected)


def test_vpxor_256bit():
    # vpxor ymm0, ymm1, ymm2 - 256-bit bitwise XOR
    val1 = 0x12345678ABCDEF9876543210FEDCBA9887654321FEDCBA9876543210ABCDEF98
    val2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    expected = val1 ^ val2

    output_state = run("c5f5efc2", ymm1=val1, ymm2=val2)
    check_output(output_state, ymm0=expected)


def test_paddd_32x4():
    # paddd xmm0, xmm1 - packed add 4×32-bit integers
    # Simple test: [1, 2, 3, 4] + [10, 20, 30, 40] = [11, 22, 33, 44]
    val1 = pack_integers([1, 2, 3, 4], 32)
    val2 = pack_integers([10, 20, 30, 40], 32)
    expected = pack_integers([11, 22, 33, 44], 32)

    output_state = run("660ffec1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_psubd_32x4():
    # psubd xmm0, xmm1 - packed subtract 4×32-bit integers
    # Simple test: [100, 50, 25, 10] - [1, 2, 3, 4] = [99, 48, 22, 6]
    val1 = pack_integers([100, 50, 25, 10], 32)
    val2 = pack_integers([1, 2, 3, 4], 32)
    expected = pack_integers([99, 48, 22, 6], 32)

    output_state = run("660ffac1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)

    # Demonstrate unpack functionality by verifying the result element by element
    result_elements = unpack_integers(output_state.ymm0, 32, 4)
    assert result_elements == [99, 48, 22, 6]


def test_paddq_64x2():
    # paddq xmm0, xmm1 - packed add 2×64-bit integers
    # Simple test: [0x100, 0x200] + [0x111, 0x222] = [0x211, 0x422]
    val1 = (0x200 << 64) | 0x100  # [0x100, 0x200]
    val2 = (0x222 << 64) | 0x111  # [0x111, 0x222]
    expected = (0x422 << 64) | 0x211  # [0x211, 0x422]

    output_state = run("660fd4c1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_psubq_64x2():
    # psubq xmm0, xmm1 - packed subtract 2×64-bit integers
    # Simple test: [0x1000, 0x2000] - [0x111, 0x222] = [0xEEF, 0x1DDE]
    val1 = (0x2000 << 64) | 0x1000  # [0x1000, 0x2000]
    val2 = (0x222 << 64) | 0x111  # [0x111, 0x222]
    expected = (0x1DDE << 64) | 0xEEF  # [0xEEF, 0x1DDE]

    output_state = run("660ffbc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_paddw_16x8():
    # paddw xmm0, xmm1 - packed add 8×16-bit integers
    # Simple test: [1, 2, 3, 4, 5, 6, 7, 8] + [10, 20, 30, 40, 50, 60, 70, 80]
    val1 = sum(i << (j * 16) for j, i in enumerate([1, 2, 3, 4, 5, 6, 7, 8]))
    val2 = sum(i << (j * 16) for j, i in enumerate([10, 20, 30, 40, 50, 60, 70, 80]))
    expected = sum(
        i << (j * 16) for j, i in enumerate([11, 22, 33, 44, 55, 66, 77, 88])
    )

    output_state = run("660ffdc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_psubw_16x8():
    # psubw xmm0, xmm1 - packed subtract 8×16-bit integers
    # Simple test: [100, 200, 300, 400, 500, 600, 700, 800] - [1, 2, 3, 4, 5, 6, 7, 8]
    val1 = sum(
        i << (j * 16) for j, i in enumerate([100, 200, 300, 400, 500, 600, 700, 800])
    )
    val2 = sum(i << (j * 16) for j, i in enumerate([1, 2, 3, 4, 5, 6, 7, 8]))
    expected = sum(
        i << (j * 16) for j, i in enumerate([99, 198, 297, 396, 495, 594, 693, 792])
    )

    output_state = run("660ff9c1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_paddb_8x16():
    # paddb xmm0, xmm1 - packed add 16×8-bit integers
    # Simple test: 16 8-bit integers addition
    val1 = sum(i << (j * 8) for j, i in enumerate(range(1, 17)))
    val2 = sum(i << (j * 8) for j, i in enumerate(range(10, 161, 10)))
    expected = sum(
        i << (j * 8)
        for j, i in enumerate(
            [11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 121, 132, 143, 154, 165, 176]
        )
    )

    output_state = run("660ffcc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_psubb_8x16():
    # psubb xmm0, xmm1 - packed subtract 16×8-bit integers
    # Simple test: subtract 1 from each element [100,101,102,...,115] - [1,1,1,...,1]
    val1 = sum(i << (j * 8) for j, i in enumerate(range(100, 116)))
    val2 = sum(1 << (j * 8) for j in range(16))
    expected = sum(i << (j * 8) for j, i in enumerate(range(99, 115)))

    output_state = run("660ff8c1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_vpaddq_64x4():
    # vpaddq ymm0, ymm1, ymm2 - AVX2 packed add 4×64-bit integers
    # Simple test: [1, 2, 3, 4] + [10, 20, 30, 40] = [11, 22, 33, 44]
    val1 = pack_integers([1, 2, 3, 4], 64)
    val2 = pack_integers([10, 20, 30, 40], 64)
    expected = pack_integers([11, 22, 33, 44], 64)

    output_state = run("c5fd d4c1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)


def test_vpsubq_64x4():
    # vpsubq ymm0, ymm1, ymm2 - AVX2 packed subtract 4×64-bit integers
    # Simple test: [100, 200, 300, 400] - [1, 2, 3, 4] = [99, 198, 297, 396]
    val1 = pack_integers([100, 200, 300, 400], 64)
    val2 = pack_integers([1, 2, 3, 4], 64)
    expected = pack_integers([99, 198, 297, 396], 64)

    output_state = run("c5fd fbc1", ymm0=val1, ymm1=val2)
    check_output(output_state, ymm0=expected)

    # Demonstrate unpack functionality by verifying the result element by element
    result_elements = unpack_integers(output_state.ymm0, 64, 4)
    assert result_elements == [99, 198, 297, 396]


def test_pmullw_16x8():
    # pmullw xmm0, xmm1 - packed multiply 8×16-bit integers (truncated)
    # Simple test: [2, 3, 4, 5, 6, 7, 8, 9] * [10, 10, 10, 10, 10, 10, 10, 10]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([2, 3, 4, 5, 6, 7, 8, 9], 16)
    val2 = pack_integers([10, 10, 10, 10, 10, 10, 10, 10], 16)
    expected = pack_integers([20, 30, 40, 50, 60, 70, 80, 90], 16)

    result = state._binop_Iop_Mul16x8(None, val1, val2)
    assert result == expected


def test_pmulld_32x4():
    # pmulld xmm0, xmm1 - packed multiply 4×32-bit integers (truncated)
    # Simple test: [100, 200, 300, 400] * [2, 3, 4, 5] = [200, 600, 1200, 2000]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([100, 200, 300, 400], 32)
    val2 = pack_integers([2, 3, 4, 5], 32)
    expected = pack_integers([200, 600, 1200, 2000], 32)

    result = state._binop_Iop_Mul32x4(None, val1, val2)
    assert result == expected


def test_vpmullw_16x16():
    # vpmullw ymm0, ymm1, ymm2 - AVX2 packed multiply 16×16-bit integers
    # Test with alternating pattern
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    input1 = [i + 1 for i in range(16)]  # [1, 2, 3, ..., 16]
    input2 = [2] * 16  # [2, 2, 2, ..., 2]
    expected_vals = [a * b for a, b in zip(input1, input2)]  # [2, 4, 6, ..., 32]

    val1 = pack_integers(input1, 16)
    val2 = pack_integers(input2, 16)
    expected = pack_integers(expected_vals, 16)

    result = state._binop_Iop_Mul16x16(None, val1, val2)
    assert result == expected


def test_vpmulld_32x8():
    # vpmulld ymm0, ymm1, ymm2 - AVX2 packed multiply 8×32-bit integers
    # Test overflow behavior (32-bit truncation)
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000], 32)
    val2 = pack_integers([1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000], 32)
    # Results: [1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000]
    expected = pack_integers(
        [1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000], 32
    )

    result = state._binop_Iop_Mul32x8(None, val1, val2)
    assert result == expected


def test_psllw_16x8():
    # psllw xmm0, imm8 - packed left shift 8×16-bit integers
    # Test: [1, 2, 4, 8, 16, 32, 64, 128] << 2 = [4, 8, 16, 32, 64, 128, 256, 512]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([1, 2, 4, 8, 16, 32, 64, 128], 16)
    shift_amount = 2
    expected = pack_integers([4, 8, 16, 32, 64, 128, 256, 512], 16)

    result = state._binop_Iop_Shl16x8(None, val1, shift_amount)
    assert result == expected


def test_pslld_32x4():
    # pslld xmm0, imm8 - packed left shift 4×32-bit integers
    # Test: [1, 10, 100, 1000] << 4 = [16, 160, 1600, 16000]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([1, 10, 100, 1000], 32)
    expected = pack_integers([16, 160, 1600, 16000], 32)

    result = state._binop_Iop_Shl32x4(None, val1, 4)
    assert result == expected


def test_psrlw_16x8():
    # psrlw xmm0, imm8 - packed logical right shift 8×16-bit integers
    # Test: [1024, 512, 256, 128, 64, 32, 16, 8] >> 2 = [256, 128, 64, 32, 16, 8, 4, 2]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([1024, 512, 256, 128, 64, 32, 16, 8], 16)
    expected = pack_integers([256, 128, 64, 32, 16, 8, 4, 2], 16)

    result = state._binop_Iop_Shr16x8(None, val1, 2)
    assert result == expected


def test_psraw_16x8():
    # psraw xmm0, imm8 - packed arithmetic right shift 8×16-bit integers
    # Test with negative numbers to verify sign extension
    # [32767, -32768, 1024, -1024, 256, -256, 64, -64] >> 2
    # Expected: [8191, -8192, 256, -256, 64, -64, 16, -16]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers(
        [32767, 65536 - 32768, 1024, 65536 - 1024, 256, 65536 - 256, 64, 65536 - 64], 16
    )
    expected = pack_integers(
        [8191, 65536 - 8192, 256, 65536 - 256, 64, 65536 - 64, 16, 65536 - 16], 16
    )

    result = state._binop_Iop_Sar16x8(None, val1, 2)
    assert result == expected


def test_psrad_32x4():
    # psrad xmm0, imm8 - packed arithmetic right shift 4×32-bit integers
    # Test with negative numbers to verify sign extension
    # [1000000, -1000000, 100000, -100000] >> 4
    # Expected: [62500, -62500, 6250, -6250]
    import archinfo

    from vexingz3.interpreter import State

    state = State(archinfo.ArchAMD64())
    val1 = pack_integers([1000000, (1 << 32) - 1000000, 100000, (1 << 32) - 100000], 32)
    expected = pack_integers([62500, (1 << 32) - 62500, 6250, (1 << 32) - 6250], 32)

    result = state._binop_Iop_Sar32x4(None, val1, 4)
    assert result == expected


# Tests for new comparison operations
def test_cmp_eq8():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test equal values
    result = state._binop_Iop_CmpEQ8(None, 42, 42)
    assert result == 1

    # Test different values
    result = state._binop_Iop_CmpEQ8(None, 42, 43)
    assert result == 0

    # Test 8-bit boundary values
    result = state._binop_Iop_CmpEQ8(None, 255, 255)
    assert result == 1

    result = state._binop_Iop_CmpEQ8(None, 0, 255)
    assert result == 0


def test_cmp_ne32():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test different values
    result = state._binop_Iop_CmpNE32(None, 42, 43)
    assert result == 1

    # Test equal values
    result = state._binop_Iop_CmpNE32(None, 42, 42)
    assert result == 0

    # Test 32-bit boundary values
    result = state._binop_Iop_CmpNE32(None, 0xFFFFFFFF, 0)
    assert result == 1


def test_cmp_ne64():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test different values
    result = state._binop_Iop_CmpNE64(None, 42, 43)
    assert result == 1

    # Test equal values
    result = state._binop_Iop_CmpNE64(None, 42, 42)
    assert result == 0

    # Test 64-bit boundary values
    result = state._binop_Iop_CmpNE64(None, 0xFFFFFFFFFFFFFFFF, 0)
    assert result == 1


def test_cmp_lt32s():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test positive numbers
    result = state._binop_Iop_CmpLT32S(None, 5, 10)
    assert result == 1

    result = state._binop_Iop_CmpLT32S(None, 10, 5)
    assert result == 0

    # Test negative numbers (signed comparison)
    result = state._binop_Iop_CmpLT32S(None, 0xFFFFFFFF, 1)  # -1 < 1
    assert result == 1

    result = state._binop_Iop_CmpLT32S(None, 1, 0xFFFFFFFF)  # 1 > -1
    assert result == 0

    # Test equal values
    result = state._binop_Iop_CmpLT32S(None, 5, 5)
    assert result == 0


def test_cmp_lt32u():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test unsigned comparison
    result = state._binop_Iop_CmpLT32U(None, 5, 10)
    assert result == 1

    result = state._binop_Iop_CmpLT32U(None, 10, 5)
    assert result == 0

    # Test with large numbers (unsigned comparison)
    result = state._binop_Iop_CmpLT32U(None, 1, 0xFFFFFFFF)  # 1 < max_uint32
    assert result == 1

    result = state._binop_Iop_CmpLT32U(None, 0xFFFFFFFF, 1)  # max_uint32 > 1
    assert result == 0

    # Test equal values
    result = state._binop_Iop_CmpLT32U(None, 5, 5)
    assert result == 0


def test_cmp_lt64u():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test unsigned comparison
    result = state._binop_Iop_CmpLT64U(None, 5, 10)
    assert result == 1

    result = state._binop_Iop_CmpLT64U(None, 10, 5)
    assert result == 0

    # Test with large numbers (unsigned comparison)
    result = state._binop_Iop_CmpLT64U(None, 1, 0xFFFFFFFFFFFFFFFF)  # 1 < max_uint64
    assert result == 1

    result = state._binop_Iop_CmpLT64U(None, 0xFFFFFFFFFFFFFFFF, 1)  # max_uint64 > 1
    assert result == 0

    # Test equal values
    result = state._binop_Iop_CmpLT64U(None, 5, 5)
    assert result == 0


def test_cmp_le32s():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test less than
    result = state._binop_Iop_CmpLE32S(None, 5, 10)
    assert result == 1

    # Test greater than
    result = state._binop_Iop_CmpLE32S(None, 10, 5)
    assert result == 0

    # Test equal (should be true for LE)
    result = state._binop_Iop_CmpLE32S(None, 5, 5)
    assert result == 1

    # Test negative numbers (signed comparison)
    result = state._binop_Iop_CmpLE32S(None, 0xFFFFFFFF, 1)  # -1 <= 1
    assert result == 1

    result = state._binop_Iop_CmpLE32S(None, 1, 0xFFFFFFFF)  # 1 > -1
    assert result == 0


def test_cmp_le32u():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test less than
    result = state._binop_Iop_CmpLE32U(None, 5, 10)
    assert result == 1

    # Test greater than
    result = state._binop_Iop_CmpLE32U(None, 10, 5)
    assert result == 0

    # Test equal (should be true for LE)
    result = state._binop_Iop_CmpLE32U(None, 5, 5)
    assert result == 1

    # Test with large numbers (unsigned comparison)
    result = state._binop_Iop_CmpLE32U(None, 1, 0xFFFFFFFF)  # 1 <= max_uint32
    assert result == 1

    result = state._binop_Iop_CmpLE32U(None, 0xFFFFFFFF, 1)  # max_uint32 > 1
    assert result == 0


def test_cmp_le64s():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test less than
    result = state._binop_Iop_CmpLE64S(None, 5, 10)
    assert result == 1

    # Test greater than
    result = state._binop_Iop_CmpLE64S(None, 10, 5)
    assert result == 0

    # Test equal (should be true for LE)
    result = state._binop_Iop_CmpLE64S(None, 5, 5)
    assert result == 1

    # Test negative numbers (signed comparison)
    result = state._binop_Iop_CmpLE64S(None, 0xFFFFFFFFFFFFFFFF, 1)  # -1 <= 1
    assert result == 1

    result = state._binop_Iop_CmpLE64S(None, 1, 0xFFFFFFFFFFFFFFFF)  # 1 > -1
    assert result == 0


def test_cmp_le64u():
    from vexingz3.interpreter import State

    state = State({}, {})

    # Test less than
    result = state._binop_Iop_CmpLE64U(None, 5, 10)
    assert result == 1

    # Test greater than
    result = state._binop_Iop_CmpLE64U(None, 10, 5)
    assert result == 0

    # Test equal (should be true for LE)
    result = state._binop_Iop_CmpLE64U(None, 5, 5)
    assert result == 1

    # Test with large numbers (unsigned comparison)
    result = state._binop_Iop_CmpLE64U(None, 1, 0xFFFFFFFFFFFFFFFF)  # 1 <= max_uint64
    assert result == 1

    result = state._binop_Iop_CmpLE64U(None, 0xFFFFFFFFFFFFFFFF, 1)  # max_uint64 > 1
    assert result == 0
