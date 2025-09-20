import archinfo
import pyvex

from vexingz3.interpreter import interpret


def run(instruction, **initial_state):
    """Helper to run instruction with given register state."""
    inp = bytes.fromhex(instruction)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())
    return interpret(irsb, initial_state)


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
