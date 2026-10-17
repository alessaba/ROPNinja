"""
x86/x86-64 gadget discovery, including the byte-level scanning behavior that
AArch64 support must not disturb.

Byte sequences here were assembled with clang:

    clang -c -target x86_64-apple-macos -o x86.o x86.s
    llvm-objdump -s -j __text x86.o
"""

import unittest

from support import FakeRange, FakeView, gadgets_for, image

POP_RDI_RET = "5fc3"
RET = "c3"
RETF = "cb"
BND_RET = "f2c3"
LEAVE_RET = "c9c3"
MOV_RET = "488b4508c3"
JMP_RET = "eb05c3"
SYSCALL_RET = "0f05c3"


class X86GadgetTest(unittest.TestCase):
    def test_byte_granular_gadgets(self):
        view = FakeView(image(POP_RDI_RET), arch_name="x86_64")
        self.assertEqual(gadgets_for(view), {0x1000: "pop rdi ; ret", 0x1001: "ret"})

    def test_backtracking_starts_at_every_offset(self):
        view = FakeView(image(MOV_RET), arch_name="x86_64")
        gadgets = gadgets_for(view, max_previous_bytes=4)
        # Offsets 2 and 3 decode to instructions that overrun the ret, so they are skipped.
        self.assertEqual(set(gadgets), {0x1000, 0x1001, 0x1004})
        self.assertEqual(gadgets[0x1000], "mov rax, qword ptr [rbp + 8] ; ret")
        self.assertEqual(gadgets[0x1001], "mov eax, dword ptr [rbp + 8] ; ret")

    def test_retf_and_prefixed_ret_encodings(self):
        self.assertEqual(
            gadgets_for(FakeView(image(RETF), arch_name="x86_64")), {0x1000: "retf"}
        )
        self.assertEqual(
            gadgets_for(FakeView(image(BND_RET), arch_name="x86_64")),
            {0x1000: "bnd ret", 0x1001: "ret"},
        )

    def test_calls_and_syscalls_do_not_break_a_gadget(self):
        view = FakeView(image(SYSCALL_RET), arch_name="x86_64")
        self.assertEqual(gadgets_for(view), {0x1000: "syscall ; ret", 0x1002: "ret"})

    def test_jumps_are_rejected_unless_enabled(self):
        view = FakeView(image(JMP_RET), arch_name="x86_64")
        self.assertEqual(gadgets_for(view), {0x1002: "ret"})
        self.assertEqual(
            gadgets_for(view, include_branches=True),
            {0x1000: "jmp 0x1007 ; ret", 0x1002: "ret"},
        )

    def test_leave_is_rejected_unless_enabled(self):
        view = FakeView(image(LEAVE_RET), arch_name="x86_64")
        self.assertEqual(gadgets_for(view), {0x1001: "ret"})
        self.assertEqual(
            gadgets_for(view, include_leave=True),
            {0x1000: "leave ; ret", 0x1001: "ret"},
        )

    def test_terminators_outside_the_scanned_range_are_ignored(self):
        base = 0x1000
        self.assertEqual(
            gadgets_for(
                FakeView(image(RET), arch_name="x86_64", segments=[FakeRange(base, base + 1)])
            ),
            {0x1000: "ret"},
        )
        self.assertEqual(
            gadgets_for(
                FakeView(image(RET + RET), arch_name="x86_64", segments=[FakeRange(base, base + 1)])
            ),
            {0x1000: "ret"},
        )
        self.assertEqual(
            gadgets_for(
                FakeView(
                    image("90" + BND_RET),
                    arch_name="x86_64",
                    segments=[FakeRange(base, base + 2)],
                )
            ),
            {},
        )


if __name__ == "__main__":
    unittest.main()
