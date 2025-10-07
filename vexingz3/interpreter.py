import operator
import struct

# Mapping from VEX type to bit width
TYPE_TO_BITWIDTH = {
    "Ity_I8": 8,
    "Ity_I16": 16,
    "Ity_I32": 32,
    "Ity_I64": 64,
    "Ity_V128": 128,
    "Ity_V256": 256,
}


class State:
    TRUE = 1
    FALSE = 0

    def __init__(self, registers=None, memory=None):
        self.registers = registers or {}
        self.temps = {}
        self.memory = memory if memory is not None else {}

    def get_register(self, reg_name, bitwidth):
        return self.registers.get(reg_name, 0)

    def set_register(self, reg_name, value):
        self.registers[reg_name] = value

    def get_temp(self, temp_name):
        return self.temps.get(temp_name, 0)

    def set_temp(self, temp_name, value):
        self.temps[temp_name] = value

    def _read_byte(self, byte_addr):
        return self.memory.get(byte_addr, 0)

    def read_memory(self, address, size_bytes):
        """Read little-endian value from memory at given address."""
        bytes_values = []
        for i in range(size_bytes):
            byte_addr = address + i
            byte_value = self._read_byte(byte_addr)
            bytes_values.append(byte_value)
        return self._concat_bits(bytes_values, 8)

    def write_memory(self, address, value, size_bytes):
        """Write little-endian value to memory at given address."""
        for i in range(size_bytes):
            byte_addr = address + i
            byte_value = (value >> (i * 8)) & 0xFF
            self.memory[byte_addr] = byte_value

    def _extract_packed_element(self, packed_value, width, index):
        """Extract a single element from a packed integer value.

        Args:
            packed_value: The packed integer containing multiple elements
            width: Bit width of each element (8, 16, 32, or 64)
            index: Zero-based index of the element to extract

        Returns:
            The extracted element as an integer
        """
        return self._mask(packed_value >> (index * width), width)

    def _packed_arithmetic(self, left, right, width, count, operation):
        """Generic helper for packed arithmetic operations.

        Args:
            left: Left operand packed value
            right: Right operand packed value
            width: Bit width of each element (8, 16, 32, or 64)
            count: Number of elements (16, 8, 4, or 2)
            operation: Function that takes (left_elem, right_elem) and returns result

        Returns:
            Packed result value
        """
        result_elements = []
        for i in range(count):
            left_elem = self._extract_packed_element(left, width, i)
            right_elem = self._extract_packed_element(right, width, i)

            # Apply operation with overflow/underflow wrapping
            result_elem = self._mask(operation(left_elem, right_elem), width)
            result_elements.append(result_elem)

        return self._concat_bits(result_elements, width)

    def _packed_shift(self, value, shift_amount, width, count, shift_op):
        """Generic helper for packed shift operations.

        Args:
            value: Packed value to shift
            shift_amount: Scalar shift amount (applies to all elements)
            width: Bit width of each element (8, 16, 32, or 64)
            count: Number of elements (32, 16, 8, 4, or 2)
            shift_op: Shift operation function (<<, >>, or arithmetic right shift)

        Returns:
            Packed result value
        """
        # Mask shift amount to valid range for the element width
        shift_amount = shift_amount & (width - 1)

        result_elements = []
        for i in range(count):
            element = self._extract_packed_element(value, width, i)

            # Apply shift operation with proper masking
            shifted_elem = self._mask(shift_op(element, shift_amount), width)
            result_elements.append(shifted_elem)

        return self._concat_bits(result_elements, width)

    def _arithmetic_right_shift(self, value, shift_amount, width):
        """Generic helper for arithmetic right shift that preserves sign bit.

        Args:
            value: Unsigned value to shift
            shift_amount: Number of bits to shift right
            width: Bit width of the value (8, 16, 32, or 64)

        Returns:
            Unsigned representation of the arithmetically shifted value
        """
        value_signed = self._to_signed(value, width)
        result_signed = value_signed >> shift_amount
        return self._from_signed(result_signed, width)

    def interpret(self, irsb):
        self._current_irsb = irsb
        for stmt in irsb.statements:
            getattr(self, f"_stmt_{stmt.__class__.__name__}", self._default_stmt)(
                stmt, irsb
            )

    def _default_stmt(self, stmt, irsb):
        raise NotImplementedError(
            f"Statement type {type(stmt)} not implemented: {stmt}"
        )

    def _stmt_IMark(self, stmt, irsb):
        # Instruction mark - just continue (no-op)
        pass

    def _stmt_AbiHint(self, stmt, irsb):
        # Instruction mark - just continue (no-op)
        pass

    def _stmt_WrTmp(self, stmt, irsb):
        # t0 = GET:I64(rax) or t0 = Add64(t2,t1)
        temp_name = f"t{stmt.tmp}"
        value = self._eval_expression(stmt.data, irsb.arch)
        self.set_temp(temp_name, value)

    def _stmt_Put(self, stmt, irsb):
        # PUT(rax) = t0 or PUT(offset=16) = t0 (8-bit)
        reg_offset = stmt.offset
        reg_name = irsb.arch.register_names.get(reg_offset)
        value = self._eval_expression(stmt.data, irsb.arch)
        if reg_name is None:
            raise NotImplementedError(f"Unknown register offset {reg_offset}")
        # Splice value into register based on data type
        (reg,) = [r for r in irsb.arch.register_list if r.vex_offset == stmt.offset]
        data_type = stmt.data.result_type(irsb.tyenv)
        bitwidth = TYPE_TO_BITWIDTH[data_type]
        current_value = self.get_register(reg_name, reg.size * 8)
        new_value = self._splice_register_value(current_value, value, bitwidth)
        self.set_register(reg_name, new_value)

    def _stmt_Store(self, stmt, irsb):
        # STle(address) = value - store to memory
        address = self._eval_expression(stmt.addr, irsb.arch)
        value = self._eval_expression(stmt.data, irsb.arch)
        # Get bit width and convert to bytes
        data_type = stmt.data.result_type(irsb.tyenv)
        bitwidth = TYPE_TO_BITWIDTH[data_type]
        size_bytes = bitwidth // 8
        self.write_memory(address, value, size_bytes)

    def _stmt_Exit(self, stmt, irsb):
        # Exit statements are control flow related - for simplicity, ignore them
        # These are generated by division operations for exception handling
        pass

    def _eval_expression(self, expr, arch):
        res = getattr(
            self, f"_eval_expr_{expr.__class__.__name__}", self._default_eval_expr
        )(expr, arch)
        self._check_expression_result_type(expr, res)
        return res

    def _check_expression_result_type(self, expr, res):
        pass  # nothing, it's for overwriting in subclasses

    def _default_eval_expr(self, expr, arch):
        raise NotImplementedError(
            f"Expression type {type(expr)} not implemented: {expr}"
        )

    def _eval_expr_Get(self, expr, arch):
        # GET:I64(rax) or GET:I8(offset=16) for al
        reg_name = arch.register_names.get(expr.offset)
        if reg_name:
            (reg,) = [
                r
                for r in self._current_irsb.arch.register_list
                if r.vex_offset == expr.offset
            ]
            reg_value = self.get_register(reg_name, reg.size * 8)
            bitwidth = TYPE_TO_BITWIDTH.get(expr.ty)
            # Extract bits based on type
            if bitwidth:
                return self._mask(reg_value, bitwidth)
            else:
                return reg_value
        return 0

    def _eval_expr_RdTmp(self, expr, arch):
        # t0, t1, etc
        temp_name = f"t{expr.tmp}"
        return self.get_temp(temp_name)

    def _eval_expr_Binop(self, expr, arch):
        # Standard 2-argument binop
        left = self._eval_expression(expr.args[0], arch)
        right = self._eval_expression(expr.args[1], arch)
        return getattr(self, f"_binop_{expr.op}", self._default_binop)(
            expr, left, right
        )

    def _eval_expr_Unop(self, expr, arch):
        arg = self._eval_expression(expr.args[0], arch)
        return getattr(self, f"_unop_{expr.op}", self._default_unop)(expr, arg)

    def _eval_expr_Triop(self, expr, arch):
        # 3-operand operations like Add32Fx4(rounding_mode, left, right)
        arg0 = self._eval_expression(expr.args[0], arch)
        arg1 = self._eval_expression(expr.args[1], arch)
        arg2 = self._eval_expression(expr.args[2], arch)
        return getattr(self, f"_triop_{expr.op}", self._default_triop)(
            expr, arg0, arg1, arg2
        )

    def _eval_expr_Const(self, expr, arch):
        return expr.con.value

    def _eval_expr_ITE(self, expr, arch):
        # If-Then-Else: condition ? then_expr : else_expr
        condition = self._eval_expression(expr.cond, arch)
        then_expr = self._eval_expression(expr.iftrue, arch)
        else_expr = self._eval_expression(expr.iffalse, arch)
        return self._select(condition, then_expr, else_expr)

    def _eval_expr_Load(self, expr, arch):
        # LDle:I64(address) - load from memory
        address = self._eval_expression(expr.addr, arch)
        # Get bit width and convert to bytes
        bitwidth = TYPE_TO_BITWIDTH[expr.ty]
        size_bytes = bitwidth // 8
        return self.read_memory(address, size_bytes)

    def _eval_expr_CCall(self, expr, arch):
        # VEX helper function calls - for simplicity, return 0 for now
        # These are typically for complex operations like flag calculations
        return 0

    def _mask(self, value, bitwidth):
        return value & ((1 << bitwidth) - 1)

    def _to_signed(self, value, bitwidth):
        """Convert unsigned value to signed based on bit width."""
        sign_bit = 1 << (bitwidth - 1)
        return value if value < sign_bit else value - (1 << bitwidth)

    def _from_signed(self, value, bitwidth):
        """Convert signed value to unsigned representation based on bit width."""
        return value & ((1 << bitwidth) - 1)

    def _select(self, condition, then_expr, else_expr):
        """Select between two expressions based on condition."""
        if condition:
            return then_expr
        else:
            return else_expr

    def _sign_extend(self, value, from_bitwidth, to_bitwidth):
        """Sign-extend value from one bit width to another."""
        signed_value = self._to_signed(value, from_bitwidth)
        return self._from_signed(signed_value, to_bitwidth)

    def _zero_extend(self, value, from_bitwidth, to_bitwidth):
        """Zero-extend value from one bit width to another."""
        return self._mask(value, from_bitwidth)

    def _splice_register_value(self, current_value, new_value, bitwidth):
        """Splice new value into register based on bit width."""
        mask = (1 << bitwidth) - 1
        return (current_value & ~mask) | (new_value & mask)

    def _extract(self, value, high_bit, low_bit):
        """Extract bits from high_bit to low_bit (inclusive) from value."""
        width = high_bit - low_bit + 1
        return self._mask(value >> low_bit, width)

    def _concat_bits(self, elements, element_width):
        """Concatenate multiple elements into a single larger value.

        Args:
            elements: List of values to concatenate (element 0 goes in low bits)
            element_width: Bit width of each element

        Returns:
            Single value with elements concatenated
        """
        result = 0
        for i, element in enumerate(elements):
            result |= self._mask(element, element_width) << (i * element_width)
        return result

    def _c_style_divmod(self, dividend, divisor):
        """C-style division that truncates towards zero (not Python floor division)."""
        if divisor == 0:
            raise ZeroDivisionError("Division by zero")

        # For positive results, both methods are the same
        if (dividend >= 0 and divisor > 0) or (dividend <= 0 and divisor < 0):
            return dividend // divisor, dividend % divisor

        # For negative results, we need to truncate towards zero
        # Python's // floors towards negative infinity, so we adjust
        quotient = -(abs(dividend) // abs(divisor))
        remainder = dividend - (quotient * divisor)
        return quotient, remainder

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

    def _binop_Iop_MullS8(self, expr, left, right):
        # Signed multiply: 8-bit * 8-bit -> 16-bit result
        left_signed = self._sign_extend(left, 8, 16)
        right_signed = self._sign_extend(right, 8, 16)
        result = left_signed * right_signed
        return self._from_signed(result, 16)

    def _binop_Iop_MullS16(self, expr, left, right):
        # Signed multiply: 16-bit * 16-bit -> 32-bit result
        left_signed = self._sign_extend(left, 16, 32)
        right_signed = self._sign_extend(right, 16, 32)
        result = left_signed * right_signed
        return self._from_signed(result, 32)

    def _binop_Iop_MullS32(self, expr, left, right):
        # Signed multiply: 32-bit * 32-bit -> 64-bit result
        left_signed = self._sign_extend(left, 32, 64)
        right_signed = self._sign_extend(right, 32, 64)
        result = left_signed * right_signed
        return self._from_signed(result, 64)

    def _binop_Iop_MullU64(self, expr, left, right):
        # Unsigned multiply: 64-bit * 64-bit -> 128-bit result
        left_64 = self._zero_extend(left, 64, 128)
        right_64 = self._zero_extend(right, 64, 128)
        return left_64 * right_64  # No need to mask, Python handles arbitrary precision

    def _binop_Iop_MullS64(self, expr, left, right):
        # Signed multiply: 64-bit * 64-bit -> 128-bit result
        left_signed = self._sign_extend(left, 64, 128)
        right_signed = self._sign_extend(right, 64, 128)
        result = left_signed * right_signed
        return self._from_signed(result, 128)

    def _binop_Iop_Shl64(self, expr, left, right):
        # Left shift: left << right, mask to 64 bits
        assert (
            0 <= right <= 63
        ), f"Shift count {right} out of range [0, 63] for 64-bit shift"
        return self._mask(left << right, 64)

    def _binop_Iop_Shr64(self, expr, left, right):
        # Logical right shift: left >> right (zero fill from left)
        assert (
            0 <= right <= 63
        ), f"Shift count {right} out of range [0, 63] for 64-bit shift"
        return self._mask(left >> right, 64)

    def _binop_Iop_Sar64(self, expr, left, right):
        # Arithmetic right shift: sign-extending right shift
        assert (
            0 <= right <= 63
        ), f"Shift count {right} out of range [0, 63] for 64-bit shift"
        return self._arithmetic_right_shift(left, right, 64)

    def _binop_Iop_Shl8(self, expr, left, right):
        return self._mask(left << right, 8)

    def _binop_Iop_Shl16(self, expr, left, right):
        return self._mask(left << right, 16)

    def _binop_Iop_Shl32(self, expr, left, right):
        return self._mask(left << right, 32)

    def _binop_Iop_Shr8(self, expr, left, right):
        return self._mask(left >> right, 8)

    def _binop_Iop_Shr16(self, expr, left, right):
        return self._mask(left >> right, 16)

    def _binop_Iop_Shr32(self, expr, left, right):
        return self._mask(left >> right, 32)

    def _binop_Iop_Sar8(self, expr, left, right):
        return self._arithmetic_right_shift(left, right, 8)

    def _binop_Iop_Sar16(self, expr, left, right):
        return self._arithmetic_right_shift(left, right, 16)

    def _binop_Iop_Sar32(self, expr, left, right):
        return self._arithmetic_right_shift(left, right, 32)

    def _binop_Iop_CmpNE8(self, expr, left, right):
        # Compare not equal: returns 1 if different, 0 if same
        return self._select(left != right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpEQ32(self, expr, left, right):
        # Compare equal: returns 1 if same, 0 if different
        return self._select(left == right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpEQ64(self, expr, left, right):
        # Compare equal: returns 1 if same, 0 if different
        return self._select(left == right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpEQ8(self, expr, left, right):
        # Compare equal: returns 1 if same, 0 if different
        return self._select(left == right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpEQ16(self, expr, left, right):
        # Compare equal: returns 1 if same, 0 if different
        return self._select(left == right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpNE32(self, expr, left, right):
        # Compare not equal: returns 1 if different, 0 if same
        return self._select(left != right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpNE64(self, expr, left, right):
        # Compare not equal: returns 1 if different, 0 if same
        return self._select(left != right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT32S(self, expr, left, right):
        # Signed 32-bit less-than comparison
        left_signed = self._to_signed(left, 32)
        right_signed = self._to_signed(right, 32)
        return self._select(left_signed < right_signed, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT32U(self, expr, left, right):
        # Unsigned 32-bit less-than comparison
        return self._select(left < right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLT64U(self, expr, left, right):
        # Unsigned 64-bit less-than comparison
        return self._select(left < right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE32S(self, expr, left, right):
        # Signed 32-bit less-than-or-equal comparison
        left_signed = self._to_signed(left, 32)
        right_signed = self._to_signed(right, 32)
        return self._select(left_signed <= right_signed, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE32U(self, expr, left, right):
        # Unsigned 32-bit less-than-or-equal comparison
        return self._select(left <= right, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE64S(self, expr, left, right):
        # Signed 64-bit less-than-or-equal comparison
        left_signed = self._to_signed(left, 64)
        right_signed = self._to_signed(right, 64)
        return self._select(left_signed <= right_signed, self.TRUE, self.FALSE)

    def _binop_Iop_CmpLE64U(self, expr, left, right):
        # Unsigned 64-bit less-than-or-equal comparison
        return self._select(left <= right, self.TRUE, self.FALSE)

    def _binop_Iop_64HLto128(self, expr, left, right):
        # Combine high:low 64-bit values into 128-bit value
        high = self._mask(left, 64)
        low = self._mask(right, 64)
        return self._concat_bits([low, high], 64)

    _binop_Iop_64HLtoV128 = _binop_Iop_64HLto128

    def _binop_Iop_32HLto64(self, expr, left, right):
        # Combine high:low 32-bit values into 64-bit value
        high = self._mask(left, 32)
        low = self._mask(right, 32)
        return self._concat_bits([low, high], 32)

    def _binop_Iop_16HLto32(self, expr, left, right):
        # Combine high:low 16-bit values into 32-bit value
        high = self._mask(left, 16)
        low = self._mask(right, 16)
        return self._concat_bits([low, high], 16)

    def _binop_Iop_DivModU128to64(self, expr, left, right):
        # Unsigned division: 128-bit dividend / 64-bit divisor
        # Returns 128-bit result: quotient in low 64 bits, remainder in high 64 bits
        dividend = left
        divisor = self._mask(right, 64)
        if divisor == 0:
            raise ZeroDivisionError("Division by zero")
        quotient = dividend // divisor
        remainder = dividend % divisor
        # Pack quotient (low) and remainder (high) into 128-bit result
        return self._concat_bits(
            [self._mask(quotient, 64), self._mask(remainder, 64)], 64
        )

    def _binop_Iop_DivModU64to32(self, expr, left, right):
        # Unsigned division: 64-bit dividend / 32-bit divisor
        # Returns 64-bit result: quotient in low 32 bits, remainder in high 32 bits
        dividend = self._mask(left, 64)
        divisor = self._mask(right, 32)
        if divisor == 0:
            raise ZeroDivisionError("Division by zero")
        quotient = dividend // divisor
        remainder = dividend % divisor
        # Pack quotient (low) and remainder (high) into 64-bit result
        return self._concat_bits(
            [self._mask(quotient, 32), self._mask(remainder, 32)], 32
        )

    def _binop_Iop_DivModS128to64(self, expr, left, right):
        # Signed division: 128-bit dividend / 64-bit divisor
        # Returns 128-bit result: quotient in low 64 bits, remainder in high 64 bits
        dividend_signed = self._to_signed(left, 128)
        divisor_signed = self._to_signed(right, 64)
        quotient, remainder = self._c_style_divmod(dividend_signed, divisor_signed)
        # Convert back to unsigned and pack
        quotient_unsigned = self._from_signed(quotient, 64)
        remainder_unsigned = self._from_signed(remainder, 64)
        return self._concat_bits(
            [self._mask(quotient_unsigned, 64), self._mask(remainder_unsigned, 64)], 64
        )

    def _binop_Iop_DivModS64to32(self, expr, left, right):
        # Signed division: 64-bit dividend / 32-bit divisor
        # Returns 64-bit result: quotient in low 32 bits, remainder in high 32 bits
        dividend_signed = self._to_signed(left, 64)
        divisor_signed = self._to_signed(right, 32)
        quotient, remainder = self._c_style_divmod(dividend_signed, divisor_signed)
        # Convert back to unsigned and pack
        quotient_unsigned = self._from_signed(quotient, 32)
        remainder_unsigned = self._from_signed(remainder, 32)
        return self._concat_bits(
            [self._mask(quotient_unsigned, 32), self._mask(remainder_unsigned, 32)], 32
        )

    def _binop_Iop_CmpLT64S(self, expr, left, right):
        # Signed 64-bit less-than comparison: returns 1 if left < right, 0 otherwise
        left_signed = self._to_signed(left, 64)
        right_signed = self._to_signed(right, 64)
        return 1 if left_signed < right_signed else 0

    def _triop_Iop_Add32Fx4(self, expr, rounding_mode, left, right):
        # Add 4 packed 32-bit floats (SSE operation)
        # For simplicity, treat as integer operations on 32-bit chunks
        # Args: rounding_mode (ignored), left_operand, right_operand

        # Extract 4x32-bit values from each 128-bit operand
        left_parts = [(left >> (i * 32)) & 0xFFFFFFFF for i in range(4)]
        right_parts = [(right >> (i * 32)) & 0xFFFFFFFF for i in range(4)]

        # Add corresponding parts (treating as unsigned for now)
        result_parts = [
            self._mask(left_parts[i] + right_parts[i], 32) for i in range(4)
        ]

        # Combine back into 128-bit result
        result = 0
        for i, part in enumerate(result_parts):
            result |= part << (i * 32)

        return self._mask(result, 128)

    # Floating point helper methods
    def _int_to_double(self, int_val):
        """Convert 64-bit integer to double precision float."""
        bytes_val = int_val.to_bytes(8, "little")
        return struct.unpack("<d", bytes_val)[0]

    def _double_to_int(self, float_val):
        """Convert double precision float to 64-bit integer."""
        bytes_val = struct.pack("<d", float_val)
        return int.from_bytes(bytes_val, "little")

    def _int_to_single(self, int_val):
        """Convert 32-bit integer to single precision float."""
        bytes_val = int_val.to_bytes(4, "little")
        return struct.unpack("<f", bytes_val)[0]

    def _single_to_int(self, float_val):
        """Convert single precision float to 32-bit integer."""
        bytes_val = struct.pack("<f", float_val)
        return int.from_bytes(bytes_val, "little")

    def _float_binop_64f0x2(self, left, right, operation):
        """
        Helper for 64-bit floating point operations on lane 0 of 2 lanes.
        Extracts lower 64 bits, performs operation, preserves upper 64 bits.
        """
        left_low = self._mask(left, 64)
        right_low = self._mask(right, 64)

        # Convert to double precision floats
        left_float = self._int_to_double(left_low)
        right_float = self._int_to_double(right_low)

        # Perform operation
        result_float = operation(left_float, right_float)

        # Convert back to integer
        result_low = self._double_to_int(result_float)

        # Preserve upper 64 bits from left operand, replace lower 64 bits
        left_high = self._extract(left, 127, 64)
        return self._concat_bits([result_low, left_high], 64)

    def _float_binop_32f0x4(self, left, right, operation):
        """
        Helper for 32-bit floating point operations on lane 0 of 4 lanes.
        Extracts lower 32 bits, performs operation, preserves upper 96 bits.
        """
        left_low = self._mask(left, 32)
        right_low = self._mask(right, 32)

        # Convert to single precision floats
        left_float = self._int_to_single(left_low)
        right_float = self._int_to_single(right_low)

        # Perform operation
        result_float = operation(left_float, right_float)

        # Convert back to integer
        result_low = self._single_to_int(result_float)

        # Preserve upper 96 bits from left operand, replace lower 32 bits
        left_upper = self._extract(left, 127, 32)
        return self._concat_bits([result_low, left_upper], 32)

    # Floating point operations
    def _binop_Iop_Add64F0x2(self, expr, left, right):
        # Double precision floating point add on lane 0 of 2 lanes
        return self._float_binop_64f0x2(left, right, lambda x, y: x + y)

    def _binop_Iop_Sub64F0x2(self, expr, left, right):
        # Double precision floating point subtract on lane 0 of 2 lanes
        return self._float_binop_64f0x2(left, right, lambda x, y: x - y)

    def _binop_Iop_Mul64F0x2(self, expr, left, right):
        # Double precision floating point multiply on lane 0 of 2 lanes
        return self._float_binop_64f0x2(left, right, lambda x, y: x * y)

    def _binop_Iop_Div64F0x2(self, expr, left, right):
        # Double precision floating point divide on lane 0 of 2 lanes
        return self._float_binop_64f0x2(left, right, lambda x, y: x / y)

    def _binop_Iop_Add32F0x4(self, expr, left, right):
        # Single precision floating point add on lane 0 of 4 lanes
        return self._float_binop_32f0x4(left, right, lambda x, y: x + y)

    def _binop_Iop_Sub32F0x4(self, expr, left, right):
        # Single precision floating point subtract on lane 0 of 4 lanes
        return self._float_binop_32f0x4(left, right, lambda x, y: x - y)

    def _binop_Iop_Mul32F0x4(self, expr, left, right):
        # Single precision floating point multiply on lane 0 of 4 lanes
        return self._float_binop_32f0x4(left, right, lambda x, y: x * y)

    def _binop_Iop_Div32F0x4(self, expr, left, right):
        # Single precision floating point divide on lane 0 of 4 lanes
        return self._float_binop_32f0x4(left, right, lambda x, y: x / y)

    # 128-bit packed logical operations
    def _binop_Iop_AndV128(self, expr, left, right):
        # 128-bit bitwise AND - operates on entire 128-bit values
        return left & right

    def _binop_Iop_OrV128(self, expr, left, right):
        # 128-bit bitwise OR - operates on entire 128-bit values
        return left | right

    def _binop_Iop_XorV128(self, expr, left, right):
        # 128-bit bitwise XOR - operates on entire 128-bit values
        return left ^ right

    # 256-bit packed logical operations
    def _binop_Iop_AndV256(self, expr, left, right):
        # 256-bit bitwise AND - operates on entire 256-bit values
        return left & right

    def _binop_Iop_OrV256(self, expr, left, right):
        # 256-bit bitwise OR - operates on entire 256-bit values
        return left | right

    def _binop_Iop_XorV256(self, expr, left, right):
        # 256-bit bitwise XOR - operates on entire 256-bit values
        return left ^ right

    # Packed integer arithmetic operations
    def _binop_Iop_Add32x4(self, expr, left, right):
        # Packed add 4×32-bit integers: [a3,a2,a1,a0] + [b3,b2,b1,b0]
        return self._packed_arithmetic(left, right, 32, 4, operator.add)

    def _binop_Iop_Sub32x4(self, expr, left, right):
        # Packed subtract 4×32-bit integers: [a3,a2,a1,a0] - [b3,b2,b1,b0]
        return self._packed_arithmetic(left, right, 32, 4, operator.sub)

    def _binop_Iop_Add64x2(self, expr, left, right):
        # Packed add 2×64-bit integers: [a1,a0] + [b1,b0] = [a1+b1,a0+b0]
        return self._packed_arithmetic(left, right, 64, 2, operator.add)

    def _binop_Iop_Sub64x2(self, expr, left, right):
        # Packed subtract 2×64-bit integers: [a1,a0] - [b1,b0] = [a1-b1,a0-b0]
        return self._packed_arithmetic(left, right, 64, 2, operator.sub)

    def _binop_Iop_Add16x8(self, expr, left, right):
        # Packed add 8×16-bit integers
        return self._packed_arithmetic(left, right, 16, 8, operator.add)

    def _binop_Iop_Sub16x8(self, expr, left, right):
        # Packed subtract 8×16-bit integers
        return self._packed_arithmetic(left, right, 16, 8, operator.sub)

    def _binop_Iop_Add8x16(self, expr, left, right):
        # Packed add 16×8-bit integers
        return self._packed_arithmetic(left, right, 8, 16, operator.add)

    def _binop_Iop_Sub8x16(self, expr, left, right):
        # Packed subtract 16×8-bit integers
        return self._packed_arithmetic(left, right, 8, 16, operator.sub)

    def _binop_Iop_Add64x4(self, expr, left, right):
        # Packed add 4×64-bit integers (AVX2): [a3,a2,a1,a0] + [b3,b2,b1,b0]
        return self._packed_arithmetic(left, right, 64, 4, operator.add)

    def _binop_Iop_Sub64x4(self, expr, left, right):
        # Packed subtract 4×64-bit integers (AVX2): [a3,a2,a1,a0] - [b3,b2,b1,b0]
        return self._packed_arithmetic(left, right, 64, 4, operator.sub)

    def _binop_Iop_Add8x32(self, expr, left, right):
        # Packed add 32×8-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 8, 32, operator.add)

    def _binop_Iop_Sub8x32(self, expr, left, right):
        # Packed subtract 32×8-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 8, 32, operator.sub)

    def _binop_Iop_Add16x16(self, expr, left, right):
        # Packed add 16×16-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 16, 16, operator.add)

    def _binop_Iop_Sub16x16(self, expr, left, right):
        # Packed subtract 16×16-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 16, 16, operator.sub)

    def _binop_Iop_Add32x8(self, expr, left, right):
        # Packed add 8×32-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 32, 8, operator.add)

    def _binop_Iop_Sub32x8(self, expr, left, right):
        # Packed subtract 8×32-bit integers (AVX2): 256-bit vector operations
        return self._packed_arithmetic(left, right, 32, 8, operator.sub)

    # Packed multiplication operations (truncated results)
    def _binop_Iop_Mul16x8(self, expr, left, right):
        # Packed multiply 8×16-bit integers (PMULLW): truncated to 16-bit results
        return self._packed_arithmetic(left, right, 16, 8, operator.mul)

    def _binop_Iop_Mul32x4(self, expr, left, right):
        # Packed multiply 4×32-bit integers (PMULLD): truncated to 32-bit results
        return self._packed_arithmetic(left, right, 32, 4, operator.mul)

    def _binop_Iop_Mul16x16(self, expr, left, right):
        # Packed multiply 16×16-bit integers (VPMULLW ymm): 256-bit AVX2
        return self._packed_arithmetic(left, right, 16, 16, operator.mul)

    def _binop_Iop_Mul32x8(self, expr, left, right):
        # Packed multiply 8×32-bit integers (VPMULLD ymm): 256-bit AVX2
        return self._packed_arithmetic(left, right, 32, 8, operator.mul)

    # Packed shift operations
    def _binop_Iop_Shl16x8(self, expr, left, right):
        # Packed left shift 8×16-bit integers (PSLLW)
        return self._packed_shift(left, right, 16, 8, operator.lshift)

    def _binop_Iop_Shl32x4(self, expr, left, right):
        # Packed left shift 4×32-bit integers (PSLLD)
        return self._packed_shift(left, right, 32, 4, operator.lshift)

    def _binop_Iop_Shl64x2(self, expr, left, right):
        # Packed left shift 2×64-bit integers (PSLLQ)
        return self._packed_shift(left, right, 64, 2, operator.lshift)

    def _binop_Iop_Shr16x8(self, expr, left, right):
        # Packed logical right shift 8×16-bit integers (PSRLW)
        return self._packed_shift(left, right, 16, 8, operator.rshift)

    def _binop_Iop_Shr32x4(self, expr, left, right):
        # Packed logical right shift 4×32-bit integers (PSRLD)
        return self._packed_shift(left, right, 32, 4, operator.rshift)

    def _binop_Iop_Shr64x2(self, expr, left, right):
        # Packed logical right shift 2×64-bit integers (PSRLQ)
        return self._packed_shift(left, right, 64, 2, operator.rshift)

    def _binop_Iop_Sar16x8(self, expr, left, right):
        # Packed arithmetic right shift 8×16-bit integers (PSRAW)
        return self._packed_shift(
            left, right, 16, 8, lambda v, s: self._arithmetic_right_shift(v, s, 16)
        )

    def _binop_Iop_Sar32x4(self, expr, left, right):
        # Packed arithmetic right shift 4×32-bit integers (PSRAD)
        return self._packed_shift(
            left, right, 32, 4, lambda v, s: self._arithmetic_right_shift(v, s, 32)
        )

    def _binop_Iop_InterleaveLO32x4(self, expr, left, right):
        # Interleave low 32-bit elements from two 128-bit vectors
        # left = [a3, a2, a1, a0], right = [b3, b2, b1, b0]
        # result = [b1, a1, b0, a0]
        a0 = self._extract_packed_element(left, 32, 0)
        a1 = self._extract_packed_element(left, 32, 1)
        b0 = self._extract_packed_element(right, 32, 0)
        b1 = self._extract_packed_element(right, 32, 1)
        return self._concat_bits([a0, b0, a1, b1], 32)

    def _binop_Iop_InterleaveLO64x2(self, expr, left, right):
        # Interleave low 64-bit elements from two 128-bit vectors
        # left = [a1, a0], right = [b1, b0]
        # result = [b0, a0]
        a0 = self._extract_packed_element(left, 64, 0)
        b0 = self._extract_packed_element(right, 64, 0)
        return self._concat_bits([a0, b0], 64)

    def _binop_Iop_InterleaveHI64x2(self, expr, left, right):
        # Interleave high 64-bit elements from two 128-bit vectors
        # left = [a1, a0], right = [b1, b0]
        # result = [b1, a1]
        a1 = self._extract_packed_element(left, 64, 1)
        b1 = self._extract_packed_element(right, 64, 1)
        return self._concat_bits([a1, b1], 64)

    def _default_binop(self, expr, left, right):
        raise NotImplementedError(f"Binop {expr.op} not implemented")

    def _default_triop(self, expr, arg0, arg1, arg2):
        raise NotImplementedError(f"Triop {expr.op} not implemented")

    def _unop_Iop_64to32(self, expr, arg):
        return self._extract(arg, 31, 0)

    def _unop_Iop_32Uto64(self, expr, arg):
        return self._zero_extend(arg, 32, 64)

    def _unop_Iop_16Uto64(self, expr, arg):
        return self._zero_extend(arg, 16, 64)

    def _unop_Iop_8Uto64(self, expr, arg):
        return self._zero_extend(arg, 8, 64)

    def _unop_Iop_64HIto32(self, expr, arg):
        return self._extract(arg, 63, 32)  # Extract high 32 bits

    def _unop_Iop_32HIto16(self, expr, arg):
        return self._extract(arg, 31, 16)  # Extract high 16 bits

    def _unop_Iop_32to16(self, expr, arg):
        return self._extract(arg, 15, 0)  # Extract low 16 bits

    def _unop_Iop_128HIto64(self, expr, arg):
        return self._extract(arg, 127, 64)  # Extract high 64 bits from 128-bit value

    _unop_Iop_V128HIto64 = _unop_Iop_128HIto64

    def _unop_Iop_128to64(self, expr, arg):
        return self._extract(arg, 63, 0)  # Extract low 64 bits from 128-bit value

    _unop_Iop_V128to64 = _unop_Iop_128to64

    def _unop_Iop_64to16(self, expr, arg):
        return self._extract(arg, 15, 0)  # Extract low 16 bits

    def _unop_Iop_64to8(self, expr, arg):
        return self._extract(arg, 7, 0)  # Extract low 8 bits

    def _unop_Iop_8Sto64(self, expr, arg):
        return self._sign_extend(arg, 8, 64)  # Sign-extend 8 to 64

    def _unop_Iop_16Sto64(self, expr, arg):
        return self._sign_extend(arg, 16, 64)  # Sign-extend 16 to 64

    def _unop_Iop_32Sto64(self, expr, arg):
        return self._sign_extend(arg, 32, 64)  # Sign-extend 32 to 64

    def _unop_Iop_16Uto32(self, expr, arg):
        return self._zero_extend(arg, 16, 32)

    def _unop_Iop_8Uto16(self, expr, arg):
        return self._zero_extend(arg, 8, 16)

    def _unop_Iop_8Uto32(self, expr, arg):
        return self._zero_extend(arg, 8, 32)

    def _unop_Iop_16Sto32(self, expr, arg):
        return self._sign_extend(arg, 16, 32)  # Sign-extend 16 to 32

    def _unop_Iop_8Sto16(self, expr, arg):
        return self._sign_extend(arg, 8, 16)  # Sign-extend 8 to 16

    def _unop_Iop_8Sto32(self, expr, arg):
        return self._sign_extend(arg, 8, 32)  # Sign-extend 8 to 32

    def _unop_Iop_16to8(self, expr, arg):
        return self._extract(arg, 7, 0)  # Extract low 8 bits from 16

    def _unop_Iop_Not8(self, expr, arg):
        return self._mask(~arg, 8)  # Bitwise NOT with 8-bit mask

    def _unop_Iop_Not16(self, expr, arg):
        return self._mask(~arg, 16)  # Bitwise NOT with 16-bit mask

    def _unop_Iop_Not32(self, expr, arg):
        return self._mask(~arg, 32)  # Bitwise NOT with 32-bit mask

    def _unop_Iop_Not64(self, expr, arg):
        return self._mask(~arg, 64)  # Bitwise NOT with 64-bit mask

    def _unop_Iop_1Uto64(self, expr, arg):
        return self._zero_extend(arg, 1, 64)

    def _unop_Iop_1Uto8(self, expr, arg):
        return self._zero_extend(arg, 1, 8)

    def _unop_Iop_64to1(self, expr, arg):
        return self._extract(arg, 0, 0)  # Extract low 1 bit

    def _unop_Iop_NotV128(self, expr, arg):
        # 128-bit bitwise NOT - complement all bits
        return (~arg) & ((1 << 128) - 1)

    def _unop_Iop_32UtoV128(self, expr, arg):
        return self._zero_extend(arg, 32, 128)

    def _unop_Iop_64UtoV128(self, expr, arg):
        return self._zero_extend(arg, 64, 128)

    def _unop_Iop_Clz64(self, expr, arg):
        if arg == 0:
            return 64
        count = 0
        for i in range(63, -1, -1):
            if arg & (1 << i):
                break
            count += 1
        return count

    _unop_Iop_ClzNat64 = _unop_Iop_Clz64

    def _default_unop(self, expr, arg):
        raise NotImplementedError(f"Unop {expr.op} not implemented")


def interpret(irsb, input_state, memory=None):
    state = State(input_state.copy(), memory or {})
    state.interpret(irsb)
    return state.registers, state.memory
