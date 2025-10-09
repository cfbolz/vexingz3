import os
import tempfile
import shutil
import vexingz3
from vexingz3.runner import run_riscv64

#############################

def load_executions(filename):
    """ load 'executions' from file """
    d = {}
    eval(compile("from %s import executions" % filename, "<string>", 'exec'), d)
    return d["executions"]

#############################

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
      
    file = tempfile.NamedTemporaryFile(suffix=".py")

    run_riscv64(code, file.name)

    copyfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), str(file.name)[5:])
    shutil.copy(file.name, copyfile)

    assert os.path.exists(file.name)

    executions = load_executions("vexingz3.test%s" % file.name.replace("/", ".")[4:-3])

    assert ".ArchRISCV64" in str(executions[0].arch.__class__)

    for i, instr in enumerate(code):
        assert executions[i].code == [instr]
    
    file.close()
    os.remove(copyfile)

def test_store():
    code = [0x0073a023] # sw x7 0(x7)

    file = tempfile.NamedTemporaryFile(suffix=".py")

    run_riscv64(code, file.name)

    copyfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), str(file.name)[5:])
    shutil.copy(file.name, copyfile)

    assert os.path.exists(file.name)

    executions = load_executions("vexingz3.test%s" % file.name.replace("/", ".")[4:-3])

    assert "(store memory (bvadd x7 #x0000000000000000)" in " ".join(str(executions[0].result_memory_values).split())

    file.close()
    os.remove(copyfile)