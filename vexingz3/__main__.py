import sys
from vexingz3.runner import run_riscv64

def _parse_args():
    i = 1
    arch, outfile, opcodes = None, None, None
    while i < len(sys.argv):
        if sys.argv[i] == "-arch":
            arch = sys.argv[i+1]
        elif sys.argv[i] == "-file":
            outfile = sys.argv[i+1]
        elif sys.argv[i] == "-opcodes":
            opcodes = [int(x) for x in sys.argv[i+1:]]
            break
        
        i += 2

    if not (arch and outfile and opcodes):
        print("please provide architecture, an output file and at least one opcode")
        print("e.g., python -m vexingz3 -arch riscv64 -file /some/file/path/file.py -opcodes 4169705603 .....")
        assert 0, "missing args"

    return arch, outfile, opcodes


if __name__ == "__main__":
    archname, outfile, opcodes = _parse_args()
    
    if archname == "riscv64" or archname == "rv64":
        run_riscv64(opcodes, outfile)
    else:
        assert 0

