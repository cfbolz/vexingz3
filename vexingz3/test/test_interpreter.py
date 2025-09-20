import archinfo
import pyvex

from vexingz3.interpreter import interpret


def test_add_rax_rbx():
    # add rax, rbx -> 4801d8 (but VEX lifts this differently)
    ADD_INSTRUCTION = "4801d8"  # add rax, rbx
    inp = bytes.fromhex(ADD_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: rax=5, rbx=3
    input_state = {
        "rax": 5,
        "rbx": 3,
    }

    output_state = interpret(irsb, input_state)

    # expected: rax should be 8 (5+3)
    assert output_state["rax"] == 8
    assert output_state["rbx"] == 3  # rbx unchanged


def test_add64_overflow():
    ADD_INSTRUCTION = "4801d8"  # add rax, rbx
    inp = bytes.fromhex(ADD_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # 64-bit overflow: adding 1 to max uint64 should wrap to 0
    input_state = {
        "rax": 0xFFFFFFFFFFFFFFFF,  # max uint64
        "rbx": 1,
    }

    output_state = interpret(irsb, input_state)

    # 64-bit overflow should wrap to 0
    assert output_state["rax"] == 0


def test_sub_rax_rbx():
    SUB_INSTRUCTION = "4829d8"  # sub rax, rbx
    inp = bytes.fromhex(SUB_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: rax=10, rbx=3
    input_state = {
        "rax": 10,
        "rbx": 3,
    }

    output_state = interpret(irsb, input_state)

    # expected: rax should be 7 (10-3)
    assert output_state["rax"] == 7
    assert output_state["rbx"] == 3  # rbx unchanged


def test_add8_al_bl():
    ADD8_INSTRUCTION = "00d8"  # add al, bl
    inp = bytes.fromhex(ADD8_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: al=5 (low 8 bits of rax), bl=179 (low 8 bits of rbx)
    input_state = {
        "rax": 0x12345678ABCDEF05,  # al = 0x05
        "rbx": 0x9876543210FEDCB3,  # bl = 0xb3
    }

    output_state = interpret(irsb, input_state)

    # expected: al should be 0x05 + 0xb3 = 0xb8 (184)
    # rax should have only al updated: 0x12345678abcdefb8
    assert output_state["rax"] == 0x12345678ABCDEFB8
    assert output_state["rbx"] == 0x9876543210FEDCB3  # rbx unchanged


def test_add16_ax_bx():
    ADD16_INSTRUCTION = "6601d8"  # add ax, bx (16-bit)
    inp = bytes.fromhex(ADD16_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: ax=0x1234 (low 16 bits of rax), bx=0x5678 (low 16 bits of rbx)
    input_state = {
        "rax": 0x12345678ABCD1234,  # ax = 0x1234
        "rbx": 0x9876543210FE5678,  # bx = 0x5678
    }

    output_state = interpret(irsb, input_state)

    # expected: ax should be 0x1234 + 0x5678 = 0x68ac
    # rax should have only ax updated: 0x12345678abcd68ac
    assert output_state["rax"] == 0x12345678ABCD68AC
    assert output_state["rbx"] == 0x9876543210FE5678  # rbx unchanged


def test_add32_eax_ebx():
    ADD32_INSTRUCTION = "01d8"  # add eax, ebx (32-bit)
    inp = bytes.fromhex(ADD32_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: eax=0x12345678 (low 32 bits of rax),
    # ebx=0x9abcdef0 (low 32 bits of rbx)
    input_state = {
        "rax": 0xFEDCBA9812345678,  # eax = 0x12345678
        "rbx": 0x123456789ABCDEF0,  # ebx = 0x9abcdef0
    }

    output_state = interpret(irsb, input_state)

    # expected: eax should be 0x12345678 + 0x9abcdef0 = 0xacf13568
    # Note: 32-bit operations in x86-64 zero the upper 32 bits
    # rax should be 0x00000000acf13568
    assert output_state["rax"] == 0x00000000ACF13568
    assert output_state["rbx"] == 0x123456789ABCDEF0  # rbx unchanged


def test_sub8_al_bl():
    SUB8_INSTRUCTION = "28d8"  # sub al, bl
    inp = bytes.fromhex(SUB8_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: al=0x80, bl=0x30
    input_state = {
        "rax": 0x12345678ABCDEF80,  # al = 0x80
        "rbx": 0x9876543210FEDC30,  # bl = 0x30
    }

    output_state = interpret(irsb, input_state)

    # expected: al should be 0x80 - 0x30 = 0x50
    # rax should have only al updated: 0x12345678abcdef50
    assert output_state["rax"] == 0x12345678ABCDEF50
    assert output_state["rbx"] == 0x9876543210FEDC30  # rbx unchanged


def test_sub16_ax_bx():
    SUB16_INSTRUCTION = "6629d8"  # sub ax, bx (16-bit)
    inp = bytes.fromhex(SUB16_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: ax=0x8000, bx=0x3000
    input_state = {
        "rax": 0x12345678ABCD8000,  # ax = 0x8000
        "rbx": 0x9876543210FE3000,  # bx = 0x3000
    }

    output_state = interpret(irsb, input_state)

    # expected: ax should be 0x8000 - 0x3000 = 0x5000
    # rax should have only ax updated: 0x12345678abcd5000
    assert output_state["rax"] == 0x12345678ABCD5000
    assert output_state["rbx"] == 0x9876543210FE3000  # rbx unchanged


def test_sub32_eax_ebx():
    SUB32_INSTRUCTION = "29d8"  # sub eax, ebx (32-bit)
    inp = bytes.fromhex(SUB32_INSTRUCTION)
    irsb = pyvex.lift(inp, 0x400000, archinfo.ArchAMD64())

    # input state: eax=0x80000000, ebx=0x30000000
    input_state = {
        "rax": 0xFEDCBA9880000000,  # eax = 0x80000000
        "rbx": 0x12345678930000000,  # ebx = 0x30000000
    }

    output_state = interpret(irsb, input_state)

    # expected: eax should be 0x80000000 - 0x30000000 = 0x50000000
    # 32-bit operations zero upper 32 bits: 0x0000000050000000
    assert output_state["rax"] == 0x0000000050000000
    assert output_state["rbx"] == 0x12345678930000000  # rbx unchanged
