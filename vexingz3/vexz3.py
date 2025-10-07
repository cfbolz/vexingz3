import z3

from vexingz3 import interpreter


class StateZ3(interpreter.State):
    TRUE = z3.BitVecVal(1, 1)
    FALSE = z3.BitVecVal(0, 1)

    def get_register(self, reg_name, bitwidth):
        return self.registers.get(reg_name, z3.BitVecVal(0, bitwidth))

    def _read_byte(self, byte_addr):
        return self.memory[byte_addr]

    def _mask(self, value, bitwidth):
        if value.sort().size() == bitwidth:
            return value
        # For Z3 expressions, use Extract to get the proper bit width
        return z3.Extract(bitwidth - 1, 0, value)

    def _binop_Iop_MullS8(self, expr, left, right):
        """Z3 implementation of signed 8-bit multiply -> 16-bit result."""
        # For Z3 expressions, sign-extend to 16-bit and multiply
        left_16 = z3.SignExt(8, left)  # 8-bit -> 16-bit signed extension
        right_16 = z3.SignExt(8, right)  # 8-bit -> 16-bit signed extension
        return left_16 * right_16

    def _zero_extend(self, value, from_bitwidth, to_bitwidth):
        """Z3 implementation of zero extension."""
        # Zero-extend using Z3
        extension_bits = to_bitwidth - from_bitwidth
        if extension_bits <= 0:
            return self._mask(value, to_bitwidth)
        return z3.ZeroExt(extension_bits, value)

    def _sign_extend(self, value, from_bitwidth, to_bitwidth):
        """Z3 implementation of sign extension."""
        # Sign-extend using Z3
        extension_bits = to_bitwidth - from_bitwidth
        if extension_bits <= 0:
            return self._mask(value, to_bitwidth)
        return z3.SignExt(extension_bits, value)

    def _extract(self, value, high_bit, low_bit):
        """Z3 implementation of bit extraction."""
        # Extract bits using Z3
        return z3.Extract(high_bit, low_bit, value)

    def _concat_bits(self, elements, element_width):
        """Z3 implementation of bit concatenation."""
        # Z3 Concat concatenates with the first argument as high bits
        # But our elements list has element 0 as low bits, so reverse
        return z3.Concat(*reversed(elements))

    def _binop_Iop_Shl64(self, expr, left, right):
        """Z3 implementation of 64-bit left shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return left << right

    def _binop_Iop_Shr64(self, expr, left, right):
        """Z3 implementation of 64-bit logical right shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return z3.LShR(left, right)

    def _binop_Iop_Sar64(self, expr, left, right):
        """Z3 implementation of 64-bit arithmetic right shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return left >> right

    def _binop_Iop_Shl32(self, expr, left, right):
        """Z3 implementation of 32-bit left shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return left << right

    def _binop_Iop_Shr32(self, expr, left, right):
        """Z3 implementation of 32-bit logical right shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return z3.LShR(left, right)

    def _binop_Iop_Sar32(self, expr, left, right):
        """Z3 implementation of 32-bit arithmetic right shift."""
        # For Z3 expressions, ensure both operands have same bit width
        if right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return left >> right

    def _check_expression_result_type(self, expr, res):
        # check that z3 bit vector sort is of the same size as the vex type says
        assert res.sort().size() == expr.result_size(self._current_irsb.tyenv)

    def _splice_register_value(self, current_value, new_value, bitwidth):
        """Z3-compatible register value splicing."""
        # For Z3 expressions, handle bit width differences
        current_bits = current_value.sort().size()
        new_bits = new_value.sort().size()

        if new_bits < current_bits:
            # Zero-extend the new value to match current value width
            new_value_extended = z3.ZeroExt(current_bits - new_bits, new_value)
        elif new_bits > current_bits:
            # This shouldn't happen in normal cases - if it does, we take lower bits
            new_value_extended = z3.Extract(current_bits - 1, 0, new_value)
        else:
            new_value_extended = new_value

        # Create mask for the bit width
        if bitwidth >= current_bits:
            # Replace the entire current value
            return new_value_extended
        else:
            # Replace only the lower 'bitwidth' bits
            mask = z3.BitVecVal((1 << bitwidth) - 1, current_bits)
            inv_mask = ~mask
            return (current_value & inv_mask) | (new_value_extended & mask)

    def _eval_expr_Const(self, expr, arch):
        width = expr.result_size(self._current_irsb.tyenv)
        return z3.BitVecVal(expr.con.value, width)

    def _binop_Iop_CmpLT64S(self, expr, left, right):
        """Z3 implementation of signed 64-bit less-than comparison."""
        # Use Z3's signed comparison directly instead of _to_signed
        return self._select(left < right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT32S(self, expr, left, right):
        """Z3 implementation of signed 32-bit less-than comparison."""
        # Use Z3's signed comparison directly instead of _to_signed
        return self._select(left < right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE32S(self, expr, left, right):
        """Z3 implementation of signed 32-bit less-than-or-equal comparison."""
        # Use Z3's signed comparison directly instead of _to_signed
        return self._select(left <= right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE64S(self, expr, left, right):
        """Z3 implementation of signed 64-bit less-than-or-equal comparison."""
        # Use Z3's signed comparison directly instead of _to_signed
        return self._select(left <= right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT32U(self, expr, left, right):
        """Z3 implementation of unsigned 32-bit less-than comparison."""
        return self._select(z3.ULT(left, right), self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT64U(self, expr, left, right):
        """Z3 implementation of unsigned 64-bit less-than comparison."""
        return self._select(z3.ULT(left, right), self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE32U(self, expr, left, right):
        """Z3 implementation of unsigned 32-bit less-than-or-equal comparison."""
        return self._select(z3.ULE(left, right), self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE64U(self, expr, left, right):
        """Z3 implementation of unsigned 64-bit less-than-or-equal comparison."""
        return self._select(z3.ULE(left, right), self.TRUE, self.FALSE)

    def _select(self, condition, then_expr, else_expr):
        """Z3 implementation of conditional selection."""
        # Use Z3's If for symbolic expressions
        # Handle both boolean expressions and bitvector conditions
        if hasattr(condition, "sort") and condition.sort().kind() == z3.Z3_BOOL_SORT:
            # Condition is already a boolean
            return z3.If(condition, then_expr, else_expr)
        else:
            # Condition is a bitvector, compare with 0
            return z3.If(condition != 0, then_expr, else_expr)
