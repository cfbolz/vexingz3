import archinfo
import pyvex
import z3

from vexingz3.vexz3 import StateZ3


def assert_z3_equivalent(actual, expected):
    """Check if two Z3 expressions are equivalent using a solver"""
    s = z3.Solver()
    s.add(actual != expected)
    result = s.check()
    assert result == z3.unsat, f"Expressions not equivalent: {actual} != {expected}"


def run(instruction, memory=None, **initial_state):
    inp = bytes.fromhex(instruction)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())
    memory = memory if memory is not None else {}

    state = StateZ3(initial_state.copy(), memory or {})
    state.interpret(irsb)
    return state.registers, state.memory


def test_add_rax_rbx():
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    output_state = run("4801d8", rax=rax, rbx=rbx)  # add rax, rbx
    assert_z3_equivalent(output_state[0]["rax"], rax + rbx)


def test_sub_rax_rbx():
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    output_state = run("4829d8", rax=rax, rbx=rbx)  # sub rax, rbx
    assert_z3_equivalent(output_state[0]["rax"], rax - rbx)


def test_add8_al_bl():
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    output_state = run("00d8", rax=rax, rbx=rbx)  # add al, bl
    # al (lower 8 bits of rax) + bl (lower 8 bits of rbx)
    al = z3.Extract(7, 0, rax)
    bl = z3.Extract(7, 0, rbx)
    result_al = al + bl
    # Result should have upper 56 bits of rax unchanged, lower 8 bits set to result_al
    expected_rax = z3.Concat(z3.Extract(63, 8, rax), result_al)
    assert_z3_equivalent(output_state[0]["rax"], expected_rax)


def test_and64_rax_rbx():
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    output_state = run("4821d8", rax=rax, rbx=rbx)  # and rax, rbx
    assert_z3_equivalent(output_state[0]["rax"], rax & rbx)


def test_xor64_rax_rbx():
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    output_state = run("4831d8", rax=rax, rbx=rbx)  # xor rax, rbx
    assert_z3_equivalent(output_state[0]["rax"], rax ^ rbx)


def test_mulls8():
    """Test MullS8: 8-bit signed multiply -> 16-bit result"""
    left = z3.BitVec("left", 8)
    right = z3.BitVec("right", 8)

    state = StateZ3({}, {})
    result = state._binop_Iop_MullS8(None, left, right)

    # Expected behavior: sign-extend 8-bit values to signed, multiply, return as 16-bit
    left_signed = z3.SignExt(8, left)  # Sign extend 8->16 bit
    right_signed = z3.SignExt(8, right)  # Sign extend 8->16 bit
    expected = left_signed * right_signed

    assert_z3_equivalent(result, expected)


def test_imul8_bl_concrete():
    """Integration test for IMUL BL with concrete values"""
    # Test case: AL = 0xFF (-1), BL = 0x02 (2) -> AX should be 0xFFFE (-2)
    output_state = run(
        "f6eb", rax=z3.BitVecVal(0xFF, 64), rbx=z3.BitVecVal(0x02, 64)
    )  # imul bl
    expected_rax = 0xFFFE  # -1 * 2 = -2 in 16-bit two's complement

    assert_z3_equivalent(output_state[0]["rax"], expected_rax)


def test_imul8_bl_symbolic():
    """Integration test for IMUL BL with symbolic values - simplified version"""
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)

    output_state = run("f6eb", rax=rax, rbx=rbx)  # imul bl
    result_rax = output_state[0]["rax"]
    expected = z3.SignExt(8, z3.Extract(7, 0, rax)) * z3.SignExt(
        8, z3.Extract(7, 0, rbx)
    )
    spliced = z3.Concat(z3.Extract(63, 16, rax), expected)

    # Test with a specific concrete example within the symbolic framework
    s = z3.Solver()
    s.add(result_rax != spliced)  # Result should be 0xFFFE

    # If the solver cannot find a model, then our implementation is correct
    assert (
        s.check() == z3.unsat
    ), "IMUL should produce correct result for AL=0xFF, BL=0x02"


def test_shl64_rax():
    """Test SHL RAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("48c1e004", rax=rax)  # shl rax, 4
    assert_z3_equivalent(output_state[0]["rax"], rax << 4)


def test_shr64_rax():
    """Test SHR RAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("48c1e804", rax=rax)  # shr rax, 4
    assert_z3_equivalent(output_state[0]["rax"], z3.LShR(rax, 4))


def test_sar64_rax():
    """Test SAR RAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("48c1f804", rax=rax)  # sar rax, 4
    assert_z3_equivalent(output_state[0]["rax"], rax >> 4)


def test_shl32_eax():
    """Test SHL EAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("c1e004", rax=rax)  # shl eax, 4
    # 32-bit operation should zero upper bits and shift lower 32 bits
    eax = z3.Extract(31, 0, rax)
    expected = z3.ZeroExt(32, eax << 4)
    assert_z3_equivalent(output_state[0]["rax"], expected)


def test_shr32_eax():
    """Test SHR EAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("c1e804", rax=rax)  # shr eax, 4
    # 32-bit operation should zero upper bits and shift lower 32 bits
    eax = z3.Extract(31, 0, rax)
    expected = z3.ZeroExt(32, z3.LShR(eax, 4))
    assert_z3_equivalent(output_state[0]["rax"], expected)


def test_sar32_eax():
    """Test SAR EAX, 4 with symbolic values"""
    rax = z3.BitVec("rax_init", 64)
    output_state = run("c1f804", rax=rax)  # sar eax, 4
    # 32-bit operation should zero upper bits and arithmetic shift lower 32 bits
    eax = z3.Extract(31, 0, rax)
    expected = z3.ZeroExt(32, eax >> 4)
    assert_z3_equivalent(output_state[0]["rax"], expected)


def test_cmp_cmovg_greater():
    """Test CMP + CMOVG when first operand is greater"""
    # cmp rax, rbx + cmovg rcx, rdx
    # When rax > rbx, should move rdx to rcx
    rax = z3.BitVec("rax_init", 64)
    rbx = z3.BitVec("rbx_init", 64)
    rcx = z3.BitVec("rcx_init", 64)
    rdx = z3.BitVec("rdx_init", 64)

    registers, memory = run("4839d8480f4fca", rax=rax, rbx=rbx, rcx=rcx, rdx=rdx)

    # Other registers should remain unchanged
    assert_z3_equivalent(registers["rax"], rax)
    assert_z3_equivalent(registers["rbx"], rbx)
    assert_z3_equivalent(registers["rdx"], rdx)

    # rcx should conditionally receive rdx based on comparison result
    # CMOVG moves when signed greater (rax > rbx)
    expected_rcx = z3.If(rax > rbx, rdx, rcx)
    assert_z3_equivalent(registers["rcx"], expected_rcx)


# Tests for new comparison operations with Z3
def test_cmp_eq8_z3():
    """Test CmpEQ8 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    # Test with symbolic values
    left = z3.BitVec("left", 8)
    right = z3.BitVec("right", 8)

    result = state._binop_Iop_CmpEQ8(None, left, right)
    expected = z3.If(left == right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_ne32_z3():
    """Test CmpNE32 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 32)
    right = z3.BitVec("right", 32)

    result = state._binop_Iop_CmpNE32(None, left, right)
    expected = z3.If(left != right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_ne64_z3():
    """Test CmpNE64 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 64)
    right = z3.BitVec("right", 64)

    result = state._binop_Iop_CmpNE64(None, left, right)
    expected = z3.If(left != right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_lt32s_z3():
    """Test CmpLT32S with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 32)
    right = z3.BitVec("right", 32)

    result = state._binop_Iop_CmpLT32S(None, left, right)
    expected = z3.If(left < right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_lt32u_z3():
    """Test CmpLT32U with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 32)
    right = z3.BitVec("right", 32)

    result = state._binop_Iop_CmpLT32U(None, left, right)
    expected = z3.If(z3.ULT(left, right), state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_lt64u_z3():
    """Test CmpLT64U with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 64)
    right = z3.BitVec("right", 64)

    result = state._binop_Iop_CmpLT64U(None, left, right)
    expected = z3.If(z3.ULT(left, right), state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_le32s_z3():
    """Test CmpLE32S with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 32)
    right = z3.BitVec("right", 32)

    result = state._binop_Iop_CmpLE32S(None, left, right)
    expected = z3.If(left <= right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_le32u_z3():
    """Test CmpLE32U with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 32)
    right = z3.BitVec("right", 32)

    result = state._binop_Iop_CmpLE32U(None, left, right)
    expected = z3.If(z3.ULE(left, right), state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_le64s_z3():
    """Test CmpLE64S with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 64)
    right = z3.BitVec("right", 64)

    result = state._binop_Iop_CmpLE64S(None, left, right)
    expected = z3.If(left <= right, state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


def test_cmp_le64u_z3():
    """Test CmpLE64U with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    left = z3.BitVec("left", 64)
    right = z3.BitVec("right", 64)

    result = state._binop_Iop_CmpLE64U(None, left, right)
    expected = z3.If(z3.ULE(left, right), state.TRUE, state.FALSE)
    assert_z3_equivalent(result, expected)


# Tests for new unary extension operations with Z3
def test_unop_8uto32_z3():
    """Test 8Uto32 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    arg = z3.BitVec("arg", 8)
    result = state._unop_Iop_8Uto32(None, arg)
    expected = z3.ZeroExt(24, arg)  # Zero-extend 8->32 (add 24 bits)
    assert_z3_equivalent(result, expected)


def test_unop_1uto8_z3():
    """Test 1Uto8 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    arg = z3.BitVec("arg", 1)
    result = state._unop_Iop_1Uto8(None, arg)
    expected = z3.ZeroExt(7, arg)  # Zero-extend 1->8 (add 7 bits)
    assert_z3_equivalent(result, expected)


def test_unop_8sto32_z3():
    """Test 8Sto32 with Z3 symbolic values"""
    from vexingz3.vexz3 import StateZ3

    state = StateZ3({}, {})

    arg = z3.BitVec("arg", 8)
    result = state._unop_Iop_8Sto32(None, arg)
    expected = z3.SignExt(24, arg)  # Sign-extend 8->32 (add 24 bits)
    assert_z3_equivalent(result, expected)
