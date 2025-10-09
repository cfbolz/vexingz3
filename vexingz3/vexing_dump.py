# This file provides fucntions for dumping vexing results into a py2 class for the pydrofoil z3backend to use

# code partially copied from https://github.com/Cskorpion/angr-z3-converter/blob/main/angrsmtdump/execution.py

# re-use this class, as its already supported by the z3backend
PY2_EXECUTION_CLASS = """class Execution(object):
    def __init__(self, code, arch, branch_size, init_regs, init_mem, res_regs, res_mem, load_addr):
        self.code = code
        self.arch = arch
        self.branch_size = branch_size
        self.init_registers = init_regs
        self.init_memory = init_mem
        self.result_reg_values = res_regs
        self.result_memory_values = res_mem 
        self.load_addr = load_addr
        self.vexingz3 = True"""


# py2.7 archinfo doesnt support rv64
# I dont want to copy over everything, so just this one class for now
STR_ARCHRISCV64 = """class ArchRISCV64():
    def __init__(self):
        self.bits = 64
        self.memory_endness  = "LE" 
        self.register_endness  = "LE" 
        self.instruction_endness  = "LE" 
        self.registers_size = {'x0': 8, 'zero': 8, 'x1': 8, 'ra': 8, 'lr': 8, 'x2': 8, 'sp': 8, 'x3': 8, 'gp': 8, 'x4': 8, 'tp': 8, 'x5': 8, 't0': 8, 'x6': 8, 't1': 8, 'x7': 8, 't2': 8, 'x8': 8, 's0': 8, 'fp': 8, 'bp': 8, 'x9': 8, 's1': 8, 'x10': 8, 'a0': 8, 'x11': 8, 'a1': 8, 'x12': 8, 'a2': 8, 'x13': 8, 'a3': 8, 'x14': 8, 'a4': 8, 'x15': 8, 'a5': 8, 'x16': 8, 'a6': 8, 'x17': 8, 'a7': 8, 'x18': 8, 's2': 8, 'x19': 8, 's3': 8, 'x20': 8, 's4': 8, 'x21': 8, 's5': 8, 'x22': 8, 's6': 8, 'x23': 8, 's7': 8, 'x24': 8, 's8': 8, 'x25': 8, 's9': 8, 'x26': 8, 's10': 8, 'x27': 8, 's11': 8, 'x28': 8, 't3': 8, 'x29': 8, 't4': 8, 'x30': 8, 't5': 8, 'x31': 8, 't6': 8, 'pc': 8, 'ip': 8, 'f0': 8, 'ft0': 8, 'f1': 8, 'ft1': 8, 'f2': 8, 'ft2': 8, 'f3': 8, 'ft3': 8, 'f4': 8, 'ft4': 8, 'f5': 8, 'ft5': 8, 'f6': 8, 'ft6': 8, 'f7': 8, 'ft7': 8, 'f8': 8, 'fs0': 8, 'f9': 8, 'fs1': 8, 'f10': 8, 'fa0': 8, 'f11': 8, 'fa1': 8, 'f12': 8, 'fa2': 8, 'f13': 8, 'fa3': 8, 'f14': 8, 'fa4': 8, 'f15': 8, 'fa5': 8, 'f16': 8, 'fa6': 8, 'f17': 8, 'fa7': 8, 'f18': 8, 'fs2': 8, 'f19': 8, 'fs3': 8, 'f20': 8, 'fs4': 8, 'f21': 8, 'fs5': 8, 'f22': 8, 'fs6': 8, 'f23': 8, 'fs7': 8, 'f24': 8, 'fs8': 8, 'f25': 8, 'fs9': 8, 'f26': 8, 'fs10': 8, 'f27': 8, 'fs11': 8, 'f28': 8, 'ft8': 8, 'f29': 8, 'ft9': 8, 'f30': 8, 'ft10': 8, 'f31': 8, 'ft11': 8, 'ip_at_syscall': 8} 
        self.register_aliases = {'x0': ['zero'], 'x1': ['ra', 'lr'], 'x2': ['sp'], 'x3': ['gp'], 'x4': ['tp'], 'x5': ['t0'], 'x6': ['t1'], 'x7': ['t2'], 'x8': ['s0', 'fp', 'bp'], 'x9': ['s1'], 'x10': ['a0'], 'x11': ['a1'], 'x12': ['a2'], 'x13': ['a3'], 'x14': ['a4'], 'x15': ['a5'], 'x16': ['a6'], 'x17': ['a7'], 'x18': ['s2'], 'x19': ['s3'], 'x20': ['s4'], 'x21': ['s5'], 'x22': ['s6'], 'x23': ['s7'], 'x24': ['s8'], 'x25': ['s9'], 'x26': ['s10'], 'x27': ['s11'], 'x28': ['t3'], 'x29': ['t4'], 'x30': ['t5'], 'x31': ['t6'], 'pc': ['ip'], 'f0': ['ft0'], 'f1': ['ft1'], 'f2': ['ft2'], 'f3': ['ft3'], 'f4': ['ft4'], 'f5': ['ft5'], 'f6': ['ft6'], 'f7': ['ft7'], 'f8': ['fs0'], 'f9': ['fs1'], 'f10': ['fa0'], 'f11': ['fa1'], 'f12': ['fa2'], 'f13': ['fa3'], 'f14': ['fa4'], 'f15': ['fa5'], 'f16': ['fa6'], 'f17': ['fa7'], 'f18': ['fs2'], 'f19': ['fs3'], 'f20': ['fs4'], 'f21': ['fs5'], 'f22': ['fs6'], 'f23': ['fs7'], 'f24': ['fs8'], 'f25': ['fs9'], 'f26': ['fs10'], 'f27': ['fs11'], 'f28': ['ft8'], 'f29': ['ft9'], 'f30': ['ft10'], 'f31': ['ft11'], 'ip_at_syscall': []} """

def dump_executions(executions, filename):
    with open(filename, "w") as outfile:
        outfile.write(STR_ARCHRISCV64)
        outfile.write("\n\n")
        outfile.write(PY2_EXECUTION_CLASS)
        outfile.write("\n\n")
        outfile.write("executions = []\n\n")
        for i, execution in enumerate(executions):
            outfile.write(execution.to_py2(str(i)))
            outfile.write("\n")
            outfile.write("executions.append(_" + str(i) + "_Execution)\n\n")

def extract_all_regs_mem(init_regs, init_mem, res_regs, res_mem, arch):
    init_regs_smt = extract_registers(init_regs, arch)
    init_memory_smt = extract_memory(init_mem)
    result_regs_smt = extract_registers(res_regs, arch)
    result_memory_smt = extract_memory(res_mem)
    return init_regs_smt, init_memory_smt, result_regs_smt, result_memory_smt

def extract_registers(registers, arch):
    smt_regs = {}
    for regname in list(arch.registers.keys()):
        smt_regs[regname] = registers[regname].sexpr()
    return smt_regs

def extract_memory(memory):
    return memory.sexpr()

class Execution(object):

    def __init__(self, code, arch, branch_size, init_regs, init_mem, res_regs, res_mem, load_addr):
        self.code = code
        self.arch = arch
        self.branch_size = branch_size
        self.init_registers = init_regs
        self.init_memory = init_mem
        self.result_reg_values = res_regs
        self.result_memory_values = res_mem 
        self.load_addr = load_addr
        self.broken = None in (res_regs, res_mem, init_regs, init_mem, arch)
        if self.broken: print((res_regs, res_mem, init_regs, init_mem, arch))

    def to_py2(self, pref=""):
        if self.broken: return " \n".join((str((self.res_regs, self.res_mem, self.init_regs, self.init_mem, self.arch)),"\'Broken\’\n"))
        code = []
        pref = "_" + pref
        code.append(pref + "_code = %s " % str(self.code))
        code.append(pref + "_arch = %s() " % str(type(self.arch)).split(".")[-1][:-2])

        code.append(pref + "_branch_size = %s " % str(self.branch_size))

        code.append(pref + "_init_registers = %s " %  str(self.init_registers))
        code.append(pref + "_init_memory = '%s' " % str(self.init_memory))
        
        code.append(pref + "_result_reg_values = %s " % str(self.result_reg_values)),
        code.append(pref + "_result_memory_values = '%s' " % str(self.result_memory_values).replace("\n", " "))

        code.append(pref + "_load_addr = %s " % str(self.load_addr))
        code.append(pref + "_Execution =  Execution(%s,%s,%s,%s,%s,%s,%s,%s)" 
                    % (pref + "_code", pref + "_arch", pref + "_branch_size",
                        pref + "_init_registers", pref + "_init_memory", 
                        pref + "_result_reg_values" ,pref + "_result_memory_values",
                        pref + "_load_addr"))
        return "\n".join(code)