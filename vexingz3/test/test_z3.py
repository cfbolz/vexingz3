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
