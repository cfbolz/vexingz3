#!/usr/bin/env python3

import archinfo

from vexingz3.interpreter import State


def test_c_style_divmod():
    state = State(archinfo.ArchAMD64())

    # Test cases from our C and Python comparison
    test_cases = [
        (7, 3, 2, 1),  # 7 / 3 = 2 remainder 1
        (-7, 3, -2, -1),  # -7 / 3 = -2 remainder -1 (C-style)
        (7, -3, -2, 1),  # 7 / -3 = -2 remainder 1 (C-style)
        (-7, -3, 2, -1),  # -7 / -3 = 2 remainder -1 (C-style)
    ]

    for dividend, divisor, expected_quotient, expected_remainder in test_cases:
        quotient, remainder = state._c_style_divmod(dividend, divisor)
        print(f"{dividend} / {divisor} = {quotient}, remainder {remainder}")
        print(f"Expected: quotient {expected_quotient}, remainder {expected_remainder}")
        assert (
            quotient == expected_quotient
        ), f"Quotient mismatch: got {quotient}, expected {expected_quotient}"
        assert (
            remainder == expected_remainder
        ), f"Remainder mismatch: got {remainder}, expected {expected_remainder}"
        print("✓ Passed\n")
