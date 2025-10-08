import archinfo
import pyvex
import z3
from vexingz3.vexz3 import StateZ3
from vexingz3.vexing_dump import Execution, dump_executions, extract_all_regs_mem

# This file acts as interface for
# - executing opcodes from the command line
# - dumping results as smtlib into a file
# This will be used for the pydrofoil z3backend (py2.7) 

# copied from test_z3.py
def run(instruction, memory=None, arch=archinfo.ArchAMD64(), registers={}):
    assert isinstance(registers, dict)
    irsb = pyvex.lift(instruction, 0x0, arch)
    memory = memory if memory is not None else {}

    state = StateZ3(registers.copy(), memory)
    state.interpret(irsb)
    return state.registers, state.memory

# code partially copied from https://github.com/Cskorpion/angr-z3-converter/blob/main/angrsmtdump/__main__.py

def init_registers_blank(arch):
    """ init registers with abstract bvs """
    init_regs = {}
    for regname, size in arch.registers.items():
        init_regs[regname] = z3.BitVec(regname, size[1] * 8)
    return init_regs 

def run_riscv64(opcodes, outfile):
    arch = archinfo.ArchRISCV64()
    
    executions = []

    for code in opcodes:
        init_mem = z3.Array("memory", z3.BitVecSort(64), z3.BitVecSort(8))
        init_regs = init_registers_blank(arch)

        mcode = code.to_bytes(4, "little")
        result_regs, result_mem = run(mcode, init_mem, arch, init_regs)

        init_regs_smt, init_memory_smt, res_regs_smt, res_memory_smt = extract_all_regs_mem(init_regs, init_mem,
                                                                                            result_regs, result_mem, arch)

        executions.append(Execution([code], arch, -1, init_regs_smt, init_memory_smt, # extra brackets and the -1 are remnants of angr # keep them
                                     res_regs_smt, res_memory_smt, 0))

    dump_executions(executions, outfile)