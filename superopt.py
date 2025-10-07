import z3

from vexingz3 import interpreter, vexz3

expr_types = {
    "Iop_Add64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_And64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_Sub64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_64to32": ("Ity_I32", ["Ity_I64"]),
    "Iop_32Uto64": ("Ity_I64", ["Ity_I32"]),
    "Iop_CmpEQ32": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_1Uto64": ("Ity_I64", ["Ity_I1"]),
    "Iop_64to1": ("Ity_I1", ["Ity_I64"]),
    "Iop_CmpEQ64": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    "Iop_Sub32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_8Uto64": ("Ity_I64", ["Ity_I8"]),
    "Iop_64to8": ("Ity_I8", ["Ity_I64"]),
    "Iop_CmpEQ8": ("Ity_I1", ["Ity_I8", "Ity_I8"]),
    "Iop_And32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_8Uto32": ("Ity_I32", ["Ity_I8"]),
    "Iop_CmpLE32S": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_CmpLT64U": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    "Iop_8Sto32": ("Ity_I32", ["Ity_I8"]),
    "Iop_MullU64": ("Ity_I128", ["Ity_I64", "Ity_I64"]),
    "Iop_128HIto64": ("Ity_I64", ["Ity_I128"]),
    "Iop_Shr64": ("Ity_I64", ["Ity_I64", "Ity_I8"]),
    "Iop_Shl64": ("Ity_I64", ["Ity_I64", "Ity_I8"]),
    "Iop_Add32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_CmpLE64U": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    "Iop_And8": ("Ity_I8", ["Ity_I8", "Ity_I8"]),
    "Iop_CmpLT32S": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_32Sto64": ("Ity_I64", ["Ity_I32"]),
    "Iop_CmpNE32": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_Not32": ("Ity_I32", ["Ity_I32"]),
    "Iop_1Uto8": ("Ity_I8", ["Ity_I1"]),
    "Iop_64UtoV128": ("Ity_V128", ["Ity_I64"]),
    "Iop_CmpNE64": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    #    "Iop_InterleaveLO64x2": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    "Iop_Sar64": ("Ity_I64", ["Ity_I64", "Ity_I8"]),
    "Iop_Or32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_CmpLE64S": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    "Iop_CmpLE32U": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_CmpLT32U": ("Ity_I1", ["Ity_I32", "Ity_I32"]),
    "Iop_Or8": ("Ity_I8", ["Ity_I8", "Ity_I8"]),
    "Iop_AndV128": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    "Iop_OrV128": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    "Iop_Mul64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_MullS64": ("Ity_I128", ["Ity_I64", "Ity_I64"]),
    "Iop_64HLto128": ("Ity_I128", ["Ity_I64", "Ity_I64"]),
    #    "Iop_DivModS128to64": ("Ity_I128", ["Ity_I128", "Ity_I64"]),
    "Iop_128to64": ("Ity_I64", ["Ity_I128"]),
    "Iop_Mul32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_Or64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_Xor64": ("Ity_I64", ["Ity_I64", "Ity_I64"]),
    "Iop_Xor32": ("Ity_I32", ["Ity_I32", "Ity_I32"]),
    "Iop_CmpNE8": ("Ity_I1", ["Ity_I8", "Ity_I8"]),
    "Iop_32UtoV128": ("Ity_V128", ["Ity_I32"]),
    # "Iop_InterleaveLO32x4": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    "Iop_16Sto32": ("Ity_I32", ["Ity_I16"]),
    "Iop_8Sto64": ("Ity_I64", ["Ity_I8"]),
    "Iop_CmpLT64S": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    "Iop_16Uto32": ("Ity_I32", ["Ity_I16"]),
    "Iop_Shr16": ("Ity_I16", ["Ity_I16", "Ity_I8"]),
    "Iop_Shl16": ("Ity_I16", ["Ity_I16", "Ity_I8"]),
    "Iop_Or16": ("Ity_I16", ["Ity_I16", "Ity_I16"]),
    "Iop_16Uto64": ("Ity_I64", ["Ity_I16"]),
    "Iop_Shr32": ("Ity_I32", ["Ity_I32", "Ity_I8"]),
    "Iop_Shl32": ("Ity_I32", ["Ity_I32", "Ity_I8"]),
    "Iop_Sar32": ("Ity_I32", ["Ity_I32", "Ity_I8"]),
    "Iop_32HLto64": ("Ity_I64", ["Ity_I32", "Ity_I32"]),
    #    "Iop_DivModS64to32": ("Ity_I64", ["Ity_I64", "Ity_I32"]),
    "Iop_64HIto32": ("Ity_I32", ["Ity_I64"]),
    "Iop_64to16": ("Ity_I16", ["Ity_I64"]),
    "Iop_CmpEQ16": ("Ity_I1", ["Ity_I16", "Ity_I16"]),
    #    "Iop_ExpCmpNE64": ("Ity_I1", ["Ity_I64", "Ity_I64"]),
    #    "Iop_Clz64": ("Ity_I64", ["Ity_I64"]),
    "Iop_Not64": ("Ity_I64", ["Ity_I64"]),
    #    "Iop_DivModU128to64": ("Ity_I128", ["Ity_I128", "Ity_I64"]),
    "Iop_16Sto64": ("Ity_I64", ["Ity_I16"]),
    "Iop_And16": ("Ity_I16", ["Ity_I16", "Ity_I16"]),
    "Iop_Add64x2": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    #    "Iop_InterleaveHI64x2": ("Ity_V128", ["Ity_V128", "Ity_V128"]),
    "Iop_V128HIto64": ("Ity_I64", ["Ity_V128"]),
    "Iop_V128to64": ("Ity_I64", ["Ity_V128"]),
    "Iop_64HLtoV128": ("Ity_V128", ["Ity_I64", "Ity_I64"]),
    "Iop_Sub8": ("Ity_I8", ["Ity_I8", "Ity_I8"]),
}

TYPE_TO_BITWIDTH = {
    "Ity_I1": 1,
    "Ity_I8": 8,
    "Ity_I16": 16,
    "Ity_I32": 32,
    "Ity_I64": 64,
    "Ity_F64": 64,
    "Ity_I128": 128,
    "Ity_V128": 128,
    "Ity_V256": 256,
}


exprs = sorted(
    expr_types.items(),
    key=lambda element: (
        TYPE_TO_BITWIDTH[element[1][0]],
        len(element[1][1]),
        TYPE_TO_BITWIDTH[element[1][1][0]],
        element[0],
    ),
)

ops_by_res = {}

for op in exprs:
    opname, (restype, argtyps) = op
    if restype not in ops_by_res:
        ops_by_res[restype] = []
    ops_by_res[restype].append(op)


is_commutative = set(
    """
Iop_CmpEQ8
Iop_CmpNE8
Iop_CmpEQ16
Iop_CmpEQ32
Iop_CmpNE32
Iop_CmpEQ64
Iop_CmpNE64
Iop_And8
Iop_Or8
Iop_And16
Iop_Or16
Iop_Add32
Iop_And32
Iop_Mul32
Iop_Or32
Iop_Xor32
Iop_Add64
Iop_And64
Iop_Mul64
Iop_Or64
Iop_Xor64
Iop_Add64x2
Iop_AndV128
Iop_OrV128
""".strip().splitlines()
)


class Superopt:
    def generate(self, length):
        if length == 0:
            yield []
            return
        for prevops in self.generate(length - 1):
            for typ in ops_by_res:
                # add a var
                yield prevops + [("var", typ, [])]

            for opname, (restype, argtyps) in exprs:
                assert len(argtyps) in (1, 2)
                if len(argtyps) == 1:
                    for arg0 in self.findarg(prevops, argtyps[0]):
                        yield prevops + [(opname, restype, [arg0])]
                else:
                    for arg0 in self.findarg(prevops, argtyps[0]):
                        for arg1 in self.findarg(prevops, argtyps[1]):
                            yield prevops + [(opname, restype, [arg0, arg1])]

    def findarg(self, prevops, typ):
        for i, op in enumerate(prevops):
            opname, restype, args = op
            if restype == typ:
                yield i


class FakeOp:
    def __init__(self, opname, args):
        self.op = opname
        self.args = args


def find_inefficiency(ops):
    import random

    values = [None] * len(ops)
    interp = interpreter.State()
    for i, op in enumerate(ops):
        opname, restype, args = op
        if opname == "var":
            value = random.randrange(0, 2 ** TYPE_TO_BITWIDTH[restype])
        elif len(args) == 1:
            arg0 = values[args[0]]
            value = getattr(interp, f"_unop_{opname}", interp._default_unop)(
                FakeOp(opname, args), arg0
            )
        else:
            assert len(args) == 2
            arg0 = values[args[0]]
            arg1 = values[args[1]]
            value = getattr(interp, f"_binop_{opname}", interp._default_binop)(
                FakeOp(opname, args), arg0, arg1
            )
        values[i] = value
        print(i, op, value)
        for j, op2 in enumerate(ops[:i]):
            if values[i] == values[j]:
                print("CANDIDATE", j)


def check_all_needed(ops, i1, i2):
    indexes = {i1, i2}
    seen = {i1, i2}
    while indexes:
        i = indexes.pop()
        opname, restype, args = ops[i]
        for arg in args:
            if arg in seen:
                continue
            indexes.add(arg)
            seen.add(arg)
    return set(range(len(ops))) == seen


def find_inefficiency_z3(ops):
    values = [None] * len(ops)
    vars = []
    interp = vexz3.StateZ3()
    solver = z3.Solver()
    conds = []
    for i, op in enumerate(ops):
        opname, restype, args = op
        var = z3.BitVec(f"v{i}", TYPE_TO_BITWIDTH[restype])
        vars.append(var)
        if opname == "var":
            value = var
        elif len(args) == 1:
            arg0 = values[args[0]]
            value = getattr(interp, f"_unop_{opname}", interp._default_unop)(
                FakeOp(opname, args), arg0
            )
        else:
            assert len(args) == 2
            arg0 = values[args[0]]
            arg1 = values[args[1]]
            value = getattr(interp, f"_binop_{opname}", interp._default_binop)(
                FakeOp(opname, args), arg0, arg1
            )
        conds.append(var == value)
        values[i] = value
    if check_all_needed(ops, i, i):
        resconst = z3.BitVec(f"c{i}", TYPE_TO_BITWIDTH[restype])
        condition = z3.ForAll(vars, z3.Implies(z3.And(*conds), values[i] == resconst))
        res = solver.check(condition)
        if res == z3.sat:
            constvalue = solver.model()[resconst].as_long()
            return ("const", constvalue)
    for j, op2 in enumerate(ops[:i]):
        if ops[j][1] != restype:
            continue
        if not check_all_needed(ops, i, j):
            continue
        # check for equality to earlier op
        res = solver.check(z3.Not(z3.Implies(z3.And(*conds), values[i] == values[j])))
        if res == z3.unsat:
            return ("prev", j)


def pattern_applies(ops, pattern):
    patternops, a, b = pattern

    def match(index, pattern_index):
        op = ops[index]
        patternop = patternops[pattern_index]
        if patternop[0] == "var":
            if pattern_index in bindings:
                return bindings[pattern_index] == index
            else:
                bindings[pattern_index] = index
                return True
        if op[0] != patternop[0]:
            return False
        for arg_op_index, arg_pattern_index in zip(op[2], patternop[2]):
            if not match(arg_op_index, arg_pattern_index):
                return False
        return True

    for i in range(len(ops)):
        bindings = {}  # index in pattern -> index in ops
        if match(i, -1):
            return True
    return False


def any_pattern_applies(ops, patterns):
    for pattern in patterns:
        if pattern_applies(ops, pattern):
            return True
    return False


def print_pattern(pattern):
    pattern, kind, res = pattern
    bindings = {}

    def tostr(i):
        opname, restype, args = pattern[i]
        if opname == "var":
            if i in bindings:
                return bindings[i]
            bindings[i] = res = f"x{len(bindings)}"
            return res
        args = ", ".join(tostr(j) for j in args)
        return f"{opname}({args})"

    if kind == "const":
        return f"{tostr(-1)} => {res}"
    if kind == "prev":
        return f"{tostr(-1)} => {tostr(res)}"
    import pdb

    pdb.set_trace()


def can_do_cse(ops):
    for i in range(len(ops)):
        for j in range(i):
            op1 = ops[i]
            op2 = ops[j]
            if op1 == op2:
                return True
    return False


def main():
    c = Superopt()
    patterns = []
    for num in range(2, 4):
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++", num)
        for ops in c.generate(num):
            if any_pattern_applies(ops, patterns):
                continue
            if can_do_cse(ops):
                continue
            try:
                # find_inefficiency(ops)
                res = find_inefficiency_z3(ops)
                if res:
                    a, b = res
                    pattern = (ops, a, b)
                    print(print_pattern(pattern))
                    patterns.append(pattern)
            except (NotImplementedError, AssertionError, z3.Z3Exception, TypeError):
                import pdb

                pdb.xpm()
                print("nope", ops)
                pass
            except Exception:
                import pdb

                pdb.xpm()
            # for i, op in enumerate(ops):
            #    print(i, op)


main()
