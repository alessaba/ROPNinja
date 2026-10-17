"""
AArch64 gadget discovery.

Instruction words in these tests were assembled with clang:

    clang -c -target arm64-apple-macos -o a64.o a64.s
    llvm-objdump -s -j __text a64.o
"""

import unittest

from bnstub import SectionSemantics
from support import FakeRange, FakeView, gadgets_for, image, words

RET = "c0035fd6"
RET_X8 = "00015fd6"
RETAA = "ff0b5fd6"
RETAB = "ff0f5fd6"
RET_X30 = RET
LDP_X29_X30 = "fd7bc1a8"  # ldp x29, x30, [sp], #16
MOV_SP_X29 = "bf030091"  # mov sp, x29
BL = "10000094"  # bl #0x40
B_EQ = "00020054"  # b.eq #0x40
CBZ = "000200b4"  # cbz x0, #0x40
BR_X16 = "00021fd6"  # br x16
BLR_X8 = "00013fd6"  # blr x8
NOP = "1f2003d5"
LDR_X8_X0_8 = "080440f9"  # ldr x8, [x0, #8]
LDR_X8_X0_POST = "088440f8"  # ldr x8, [x0], #8
LDR_X0_SP_8 = "e00740f9"  # ldr x0, [sp, #8]
STP_X29_X30 = "fd7bbfa9"  # stp x29, x30, [sp, #-16]!
MRS_X0_NZCV = "00423bd5"  # mrs x0, nzcv
ERET = "e0039fd6"
MOV_X0_X1 = "e00301aa"


class AArch64GadgetTest(unittest.TestCase):
    def test_ret_ends_a_gadget(self):
        self.assertEqual(gadgets_for(FakeView(words(RET))), {0x1000: "ret"})

    def test_instructions_before_ret_become_gadgets(self):
        view = FakeView(words(NOP, MOV_X0_X1, RET))
        self.assertEqual(
            gadgets_for(view),
            {
                0x1000: "nop ; mov x0, x1 ; ret",
                0x1004: "mov x0, x1 ; ret",
                0x1008: "ret",
            },
        )

    def test_backtrack_is_limited_by_bytes_and_alignment(self):
        view = FakeView(words(NOP, MOV_X0_X1, RET))
        # The ret is 8 bytes into the image, so a smaller budget floors to the ret itself.
        self.assertEqual(gadgets_for(view, max_previous_bytes=3), {0x1008: "ret"})
        self.assertEqual(gadgets_for(view, max_previous_bytes=4), {0x1004: "mov x0, x1 ; ret", 0x1008: "ret"})
        self.assertEqual(
            gadgets_for(view, max_previous_bytes=8),
            {
                0x1000: "nop ; mov x0, x1 ; ret",
                0x1004: "mov x0, x1 ; ret",
                0x1008: "ret",
            },
        )

    def test_earlier_ret_breaks_the_window(self):
        view = FakeView(words(RET, RET))
        gadgets = gadgets_for(view)
        self.assertEqual(gadgets, {0x1000: "ret", 0x1004: "ret"})
        self.assertNotIn(" ; ", "".join(gadgets.values()))

    def test_pointer_auth_and_register_rets_are_terminators(self):
        view = FakeView(words(RETAA, NOP, RETAB, RET_X8))
        self.assertEqual(
            gadgets_for(view),
            {
                0x1000: "retaa",
                0x1004: "nop ; retab",
                0x1008: "retab",
                0x100c: "ret x8",
            },
        )

    def test_typical_epilogue_is_discovered(self):
        view = FakeView(words(STP_X29_X30, LDR_X8_X0_8, LDP_X29_X30, RET))
        self.assertEqual(
            gadgets_for(view),
            {
                0x1000: "stp x29, x30, [sp, #-0x10]! ; ldr x8, [x0, #8] ; "
                "ldp x29, x30, [sp], #0x10 ; ret",
                0x1004: "ldr x8, [x0, #8] ; ldp x29, x30, [sp], #0x10 ; ret",
                0x1008: "ldp x29, x30, [sp], #0x10 ; ret",
                0x100c: "ret",
            },
        )

    def test_eret_is_an_ordinary_instruction(self):
        view = FakeView(words(MRS_X0_NZCV, ERET, RET))
        self.assertEqual(
            gadgets_for(view),
            {
                0x1000: "mrs x0, nzcv ; eret ; ret",
                0x1004: "eret ; ret",
                0x1008: "ret",
            },
        )

    def test_call_instructions_do_not_break_a_gadget(self):
        view = FakeView(words(BL, RET))
        self.assertEqual(gadgets_for(view), {0x1000: "bl #0x1040 ; ret", 0x1004: "ret"})


class AArch64BranchTest(unittest.TestCase):
    def test_branches_are_rejected_unless_enabled(self):
        view = FakeView(words(LDR_X8_X0_8, B_EQ, RET))
        self.assertEqual(gadgets_for(view), {0x1008: "ret"})
        self.assertEqual(
            gadgets_for(view, include_branches=True),
            {
                0x1000: "ldr x8, [x0, #8] ; b.eq #0x1044 ; ret",
                0x1004: "b.eq #0x1044 ; ret",
                0x1008: "ret",
            },
        )

    def test_conditional_branches_are_not_terminators(self):
        view = FakeView(words(NOP, CBZ, RET))
        gadgets = gadgets_for(view, include_branches=True)
        self.assertEqual(set(gadgets), {0x1000, 0x1004, 0x1008})
        self.assertTrue(gadgets[0x1004].endswith("; ret"))

    def test_indirect_branches_terminate_gadgets_when_enabled(self):
        view = FakeView(words(LDR_X8_X0_POST, BR_X16, LDR_X0_SP_8, RET))
        self.assertEqual(
            gadgets_for(view),
            {0x1008: "ldr x0, [sp, #8] ; ret", 0x100c: "ret"},
        )
        self.assertEqual(
            gadgets_for(view, include_branches=True),
            {
                0x1000: "ldr x8, [x0], #8 ; br x16 ; ldr x0, [sp, #8] ; ret",
                0x1004: "br x16 ; ldr x0, [sp, #8] ; ret",
                0x1008: "ldr x0, [sp, #8] ; ret",
                0x100c: "ret",
            },
        )

    def test_indirect_calls_terminate_gadgets_when_enabled(self):
        view = FakeView(words(LDR_X8_X0_POST, BLR_X8))
        self.assertEqual(gadgets_for(view), {})
        self.assertEqual(
            gadgets_for(view, include_branches=True),
            {0x1000: "ldr x8, [x0], #8 ; blr x8", 0x1004: "blr x8"},
        )


class AArch64LeaveTest(unittest.TestCase):
    def test_frame_teardown_needs_the_leave_setting(self):
        view = FakeView(words(MOV_SP_X29, LDP_X29_X30, RET))
        self.assertEqual(
            gadgets_for(view),
            {0x1004: "ldp x29, x30, [sp], #0x10 ; ret", 0x1008: "ret"},
        )
        self.assertEqual(
            gadgets_for(view, include_leave=True),
            {
                0x1000: "mov sp, x29 ; ldp x29, x30, [sp], #0x10 ; ret",
                0x1004: "ldp x29, x30, [sp], #0x10 ; ret",
                0x1008: "ret",
            },
        )

    def test_stack_pointer_arithmetic_is_not_leave(self):
        view = FakeView(image("ff430091", RET))  # add sp, sp, #16 ; ret
        self.assertEqual(gadgets_for(view), {0x1000: "add sp, sp, #0x10 ; ret", 0x1004: "ret"})


class AArch64PatternScanTest(unittest.TestCase):
    def test_unaligned_ret_encodings_are_ignored(self):
        # 5F D6 at offsets 0 and 1 of an image: never the upper half of a word.
        view = FakeView(image(b"\x5f\xd6\x00\x00", b"\x00\x5f\xd6\x00", NOP, RET))
        self.assertEqual(gadgets_for(view), {0x1008: "nop ; ret", 0x100c: "ret"})

    def test_truncated_ret_at_range_end_is_ignored(self):
        base = 0x1000
        image_bytes = words(NOP, RET)
        truncated = FakeView(image_bytes, segments=[FakeRange(base, base + 6)])
        self.assertEqual(gadgets_for(truncated), {})
        self.assertEqual(gadgets_for(FakeView(image_bytes)), {0x1000: "nop ; ret", 0x1004: "ret"})

    def test_misaligned_view_finds_no_gadgets(self):
        self.assertEqual(gadgets_for(FakeView(words(RET), base=0x1002)), {})

    def test_code_sections_are_used_when_there_are_no_segments(self):
        base = 0x1000
        view = FakeView(
            words(NOP, RET),
            segments=[],
            sections={
                "__text": FakeRange(
                    base, base + 8, executable=False, semantics=SectionSemantics.ReadOnlyCodeSectionSemantics
                )
            },
        )
        self.assertEqual(gadgets_for(view), {0x1000: "nop ; ret", 0x1004: "ret"})

    def test_cancellation_stops_the_search(self):
        view = FakeView(words(NOP, RET))
        self.assertEqual(gadgets_for(view, should_cancel=lambda: True), {})


if __name__ == "__main__":
    unittest.main()
