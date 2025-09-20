import archinfo
import pyvex

# translate an AMD64 basic block (of nops) at 0x400400 into VEX
MOV_INSTRUCTION = "48c7c034120000"  # mov rax, 0x1234
ADD_INSTRUCTION = "4801d8"  # add rax, rbx
PUSH_INSTRUCTION = "50"  # push rax
POP_INSTRUCTION = "58"  # pop rax
inp = bytes.fromhex(
    MOV_INSTRUCTION + ADD_INSTRUCTION + PUSH_INSTRUCTION + POP_INSTRUCTION
)
irsb = pyvex.lift(inp, 0x400400, archinfo.ArchAMD64(), opt_level=2)
import pdb

pdb.set_trace()

# pretty-print the basic block
irsb.pp()

# iterate through each statement and print all the statements
for stmt in irsb.statements:
    stmt.pp()
