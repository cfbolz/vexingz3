import z3

from vexingz3 import interpreter


class StateZ3(interpreter.State):
    def _mask(self, value, bitwidth):
        if value.sort().size() == bitwidth:
            return value
        # For Z3 expressions, use Extract to get the proper bit width
        return z3.Extract(bitwidth - 1, 0, value)

    def _binop_Iop_MullS8(self, expr, left, right):
        """Z3 implementation of signed 8-bit multiply -> 16-bit result."""
        if isinstance(left, int) and isinstance(right, int):
            # Fall back to parent implementation for concrete values
            return super()._binop_Iop_MullS8(expr, left, right)

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

    def _unop_Iop_64to32(self, expr, arg):
        """Z3 implementation of 64-bit to 32-bit conversion."""
        if isinstance(arg, int):
            return super()._unop_Iop_64to32(expr, arg)
        # Extract lower 32 bits
        return z3.Extract(31, 0, arg)

    def _sign_extend(self, value, from_bitwidth, to_bitwidth):
        """Z3 implementation of sign extension."""
        if isinstance(value, int):
            return super()._sign_extend(value, from_bitwidth, to_bitwidth)
        # Sign-extend using Z3
        extension_bits = to_bitwidth - from_bitwidth
        if extension_bits <= 0:
            return self._mask(value, to_bitwidth)
        return z3.SignExt(extension_bits, value)

    def _binop_Iop_Shl64(self, expr, left, right):
        """Z3 implementation of 64-bit left shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Shl64(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 64)
        elif right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return left << right

    def _binop_Iop_Shr64(self, expr, left, right):
        """Z3 implementation of 64-bit logical right shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Shr64(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 64)
        elif right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return z3.LShR(left, right)

    def _binop_Iop_Sar64(self, expr, left, right):
        """Z3 implementation of 64-bit arithmetic right shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Sar64(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 64)
        elif right.sort().size() < 64:
            right = z3.ZeroExt(64 - right.sort().size(), right)
        return left >> right

    def _binop_Iop_Shl32(self, expr, left, right):
        """Z3 implementation of 32-bit left shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Shl32(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 32)
        elif right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return left << right

    def _binop_Iop_Shr32(self, expr, left, right):
        """Z3 implementation of 32-bit logical right shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Shr32(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 32)
        elif right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return z3.LShR(left, right)

    def _binop_Iop_Sar32(self, expr, left, right):
        """Z3 implementation of 32-bit arithmetic right shift."""
        if isinstance(left, int) and isinstance(right, int):
            return super()._binop_Iop_Sar32(expr, left, right)
        # For Z3 expressions, ensure both operands have same bit width
        if isinstance(right, int):
            right = z3.BitVecVal(right, 32)
        elif right.sort().size() < 32:
            right = z3.ZeroExt(32 - right.sort().size(), right)
        elif right.sort().size() > 32:
            right = z3.Extract(31, 0, right)
        return left >> right

    def _check_expression_result_type(self, expr, res):
        # check that z3 bit vector sort is of the same size as the vex type says
        assert res.sort().size() == expr.result_size(self._current_irsb.tyenv)

    def _splice_register_value(self, current_value, new_value, bitwidth):
        """Z3-compatible register value splicing."""
        if isinstance(current_value, int) and isinstance(new_value, int):
            return super()._splice_register_value(current_value, new_value, bitwidth)

        # Convert integers to Z3 BitVecs if needed
        if isinstance(current_value, int):
            current_value = z3.BitVecVal(current_value, 64)  # Default to 64-bit
        if isinstance(new_value, int):
            new_value = z3.BitVecVal(new_value, 64)  # Default to 64-bit

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
