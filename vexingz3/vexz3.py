import pyvex
import z3

from vexingz3 import interpreter


class StateZ3(interpreter.State):
    def _mask(self, value, bitwidth):
        if isinstance(value, int):
            return z3.BitVecVal(value, bitwidth)
        if value.sort().size() == bitwidth:
            return value
        return value & ((1 << bitwidth) - 1)

    def _binop_Iop_MullS8(self, expr, left, right):
        """Z3 implementation of signed 8-bit multiply -> 16-bit result."""
        if isinstance(left, int) and isinstance(right, int):
            # Fall back to parent implementation for concrete values
            return super()._binop_Iop_MullS8(expr, left, right)

        # For Z3 expressions, sign-extend to 16-bit and multiply
        left_16 = z3.SignExt(8, left)  # 8-bit -> 16-bit signed extension
        right_16 = z3.SignExt(8, right)  # 8-bit -> 16-bit signed extension
        return left_16 * right_16

    def _splice_register_value(self, current_value, new_value, bitwidth):
        """Z3-compatible register value splicing."""
        if isinstance(current_value, int) and isinstance(new_value, int):
            # Fall back to parent logic for concrete values
            mask = (1 << bitwidth) - 1
            return (current_value & ~mask) | (new_value & mask)

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

    def _handle_put_statement(self, stmt, irsb):
        """Z3-compatible PUT statement handling."""
        reg_offset = stmt.offset
        reg_name = irsb.arch.register_names.get(reg_offset)
        value = self._eval_expression(stmt.data, irsb.arch)
        if reg_name is None:
            raise NotImplementedError(f"Unknown register offset {reg_offset}")

        # Splice value into register based on data type
        data_type = stmt.data.result_type(irsb.tyenv)
        bitwidth = interpreter.TYPE_TO_BITWIDTH[data_type]
        current_value = self.get_register(reg_name)

        # Use Z3-compatible splicing
        new_value = self._splice_register_value(current_value, value, bitwidth)
        self.set_register(reg_name, new_value)

    def interpret(self, irsb):
        """Z3-compatible interpreter that handles PUT statements specially."""
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                continue
            elif isinstance(stmt, pyvex.stmt.WrTmp):
                # t0 = GET:I64(rax) or t0 = Add64(t2,t1)
                temp_name = f"t{stmt.tmp}"
                value = self._eval_expression(stmt.data, irsb.arch)
                self.set_temp(temp_name, value)
            elif isinstance(stmt, pyvex.stmt.Put):
                # Use Z3-compatible PUT handling
                self._handle_put_statement(stmt, irsb)
            elif isinstance(stmt, pyvex.stmt.Store):
                # STle(address) = value - store to memory
                address = self._eval_expression(stmt.addr, irsb.arch)
                value = self._eval_expression(stmt.data, irsb.arch)
                # Get bit width and convert to bytes
                data_type = stmt.data.result_type(irsb.tyenv)
                bitwidth = interpreter.TYPE_TO_BITWIDTH[data_type]
                size_bytes = bitwidth // 8
                self.write_memory(address, value, size_bytes)
