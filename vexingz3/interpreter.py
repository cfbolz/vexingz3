import pyvex

# Mapping from VEX type to bit width
TYPE_TO_BITWIDTH = {
    "Ity_I8": 8,
    "Ity_I16": 16,
    "Ity_I32": 32,
    "Ity_I64": 64,
}


class State:
    def __init__(self, registers=None):
        self.registers = registers or {}
        self.temps = {}

    def get_register(self, reg_name):
        return self.registers.get(reg_name, 0)

    def set_register(self, reg_name, value):
        self.registers[reg_name] = value

    def get_temp(self, temp_name):
        return self.temps.get(temp_name, 0)

    def set_temp(self, temp_name, value):
        self.temps[temp_name] = value

    def interpret(self, irsb):
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                continue
            elif isinstance(stmt, pyvex.stmt.WrTmp):
                # t0 = GET:I64(rax) or t0 = Add64(t2,t1)
                temp_name = f"t{stmt.tmp}"
                value = self._eval_expression(stmt.data, irsb.arch)
                self.set_temp(temp_name, value)
            elif isinstance(stmt, pyvex.stmt.Put):
                # PUT(rax) = t0 or PUT(offset=16) = t0 (8-bit)
                reg_offset = stmt.offset
                reg_name = irsb.arch.register_names.get(reg_offset)
                value = self._eval_expression(stmt.data, irsb.arch)
                if reg_name is None:
                    raise NotImplementedError(f"Unknown register offset {reg_offset}")
                # Splice value into register based on data type
                data_type = stmt.data.result_type(irsb.tyenv)
                bitwidth = TYPE_TO_BITWIDTH.get(data_type, 64)
                current_value = self.get_register(reg_name)
                mask = (1 << bitwidth) - 1
                new_value = (current_value & ~mask) | (value & mask)
                self.set_register(reg_name, new_value)

    def _eval_expression(self, expr, arch):
        if isinstance(expr, pyvex.expr.Get):
            # GET:I64(rax) or GET:I8(offset=16) for al
            reg_name = arch.register_names.get(expr.offset)
            if reg_name:
                reg_value = self.get_register(reg_name)
                # Extract bits based on type
                bitwidth = TYPE_TO_BITWIDTH.get(expr.ty)
                if bitwidth:
                    return self._mask(reg_value, bitwidth)
                else:
                    return reg_value
            return 0
        elif isinstance(expr, pyvex.expr.RdTmp):
            # t0, t1, etc
            temp_name = f"t{expr.tmp}"
            return self.get_temp(temp_name)
        elif isinstance(expr, pyvex.expr.Binop):
            left = self._eval_expression(expr.args[0], arch)
            right = self._eval_expression(expr.args[1], arch)
            return getattr(self, f"_binop_{expr.op}", self._default_binop)(
                expr, left, right
            )
        elif isinstance(expr, pyvex.expr.Unop):
            arg = self._eval_expression(expr.args[0], arch)
            return getattr(self, f"_unop_{expr.op}", self._default_unop)(expr, arg)
        elif isinstance(expr, pyvex.expr.Const):
            return expr.con.value

        return 0

    def _mask(self, value, bitwidth):
        return value & ((1 << bitwidth) - 1)

    def _binop_Iop_Add64(self, expr, left, right):
        return self._mask(left + right, 64)

    def _binop_Iop_Sub64(self, expr, left, right):
        return self._mask(left - right, 64)

    def _binop_Iop_Sub8(self, expr, left, right):
        return self._mask(left - right, 8)

    def _binop_Iop_Sub16(self, expr, left, right):
        return self._mask(left - right, 16)

    def _binop_Iop_Sub32(self, expr, left, right):
        return self._mask(left - right, 32)

    def _binop_Iop_Add8(self, expr, left, right):
        return self._mask(left + right, 8)

    def _binop_Iop_Add16(self, expr, left, right):
        return self._mask(left + right, 16)

    def _binop_Iop_Add32(self, expr, left, right):
        return self._mask(left + right, 32)

    def _binop_Iop_And8(self, expr, left, right):
        return self._mask(left & right, 8)

    def _binop_Iop_And16(self, expr, left, right):
        return self._mask(left & right, 16)

    def _binop_Iop_And32(self, expr, left, right):
        return self._mask(left & right, 32)

    def _binop_Iop_And64(self, expr, left, right):
        return self._mask(left & right, 64)

    def _binop_Iop_Or8(self, expr, left, right):
        return self._mask(left | right, 8)

    def _binop_Iop_Or16(self, expr, left, right):
        return self._mask(left | right, 16)

    def _binop_Iop_Or32(self, expr, left, right):
        return self._mask(left | right, 32)

    def _binop_Iop_Or64(self, expr, left, right):
        return self._mask(left | right, 64)

    def _binop_Iop_Xor8(self, expr, left, right):
        return self._mask(left ^ right, 8)

    def _binop_Iop_Xor16(self, expr, left, right):
        return self._mask(left ^ right, 16)

    def _binop_Iop_Xor32(self, expr, left, right):
        return self._mask(left ^ right, 32)

    def _binop_Iop_Xor64(self, expr, left, right):
        return self._mask(left ^ right, 64)

    def _binop_Iop_Mul8(self, expr, left, right):
        return self._mask(left * right, 8)

    def _binop_Iop_Mul16(self, expr, left, right):
        return self._mask(left * right, 16)

    def _binop_Iop_Mul32(self, expr, left, right):
        return self._mask(left * right, 32)

    def _binop_Iop_Mul64(self, expr, left, right):
        return self._mask(left * right, 64)

    def _binop_Iop_MullU8(self, expr, left, right):
        # Unsigned multiply: 8-bit * 8-bit -> 16-bit result
        left_8 = self._mask(left, 8)
        right_8 = self._mask(right, 8)
        return left_8 * right_8  # No need to mask, result fits in 16 bits

    def _binop_Iop_MullU16(self, expr, left, right):
        # Unsigned multiply: 16-bit * 16-bit -> 32-bit result
        left_16 = self._mask(left, 16)
        right_16 = self._mask(right, 16)
        return left_16 * right_16  # No need to mask, result fits in 32 bits

    def _binop_Iop_MullU32(self, expr, left, right):
        # Unsigned multiply: 32-bit * 32-bit -> 64-bit result
        left_32 = self._mask(left, 32)
        right_32 = self._mask(right, 32)
        return left_32 * right_32  # No need to mask, result fits in 64 bits

    def _default_binop(self, expr, left, right):
        raise NotImplementedError(f"Binop {expr.op} not implemented")

    def _unop_Iop_64to32(self, expr, arg):
        return self._mask(arg, 32)

    def _unop_Iop_32Uto64(self, expr, arg):
        return self._mask(arg, 32)  # zero-extend to 64 bits (already done by mask)

    def _unop_Iop_16Uto64(self, expr, arg):
        return self._mask(arg, 16)  # zero-extend to 64 bits (already done by mask)

    def _unop_Iop_8Uto64(self, expr, arg):
        return self._mask(arg, 8)  # zero-extend to 64 bits (already done by mask)

    def _unop_Iop_64HIto32(self, expr, arg):
        return self._mask(arg >> 32, 32)  # Extract high 32 bits

    def _unop_Iop_32HIto16(self, expr, arg):
        return self._mask(arg >> 16, 16)  # Extract high 16 bits

    def _unop_Iop_32to16(self, expr, arg):
        return self._mask(arg, 16)  # Extract low 16 bits

    def _default_unop(self, expr, arg):
        raise NotImplementedError(f"Unop {expr.op} not implemented")


def interpret(irsb, input_state):
    state = State(input_state.copy())
    state.interpret(irsb)
    return state.registers
