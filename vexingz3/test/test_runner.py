import os
from vexingz3.runner import run_riscv64

def test_dump_simple():
    code = [
        0x07300613, # li   x12 x0  115
        0x003f71b3, # and  x3  x30 x3
        0x03f71a13, # slli x20 x14 63 
        0x3e804093, # xori x1  x0 1000
        0x00000013, # nop = addi x0 x0 0
        #0x0073a023, # fence
        0x04d3e893, # ori  x17 x7 77 
    ]
      
    file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_executions.py")

    run_riscv64(code, file)

    assert os.path.exists(file)

    from vexingz3.test.test_executions import executions

    assert "test_executions.ArchRISCV64" in str(executions[0].arch.__class__)

    for i, instr in enumerate(code):
        assert executions[i].code == [instr]
    
    os.remove(file)

def test_store():
    code = [0x0073a023] # sw x7 0(x7)

    file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_executions.py")

    run_riscv64(code, file)

    assert os.path.exists(file)

    from vexingz3.test.test_executions import executions

    assert "????" in executions[0].result_memory_values

    os.remove(file)