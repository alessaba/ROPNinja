"""
Sidebar categories and display rows for both architectures.
"""

import unittest

from support import FakeView, gadgets_for, image, words

from ropninja import (
    find_rop_gadgets_in_view,
    format_gadget_rows_for_display,
    matches_gadget_category,
)

AARCH64_EPILOGUE = "ldp x29, x30, [sp], #0x10 ; ret"

X86_CATEGORIES = [
    ("pop rdi ; ret", "pop", True),
    ("pop rdi ; ret", "branch", False),
    ("mov rax, qword ptr [rbp + 8] ; ret", "mov", True),
    ("call 0x1234 ; ret", "call", True),
    ("leave ; ret", "leave", True),
    ("leave ; ret", "stack", True),
    ("pop rsp ; ret", "stack", True),
    ("xchg rsp, rax ; ret", "stack", True),
    ("jmp 0x1007 ; ret", "branch", True),
    ("ret", "pop", False),
    ("ret", "leave", False),
]

AARCH64_CATEGORIES = [
    (AARCH64_EPILOGUE, "pop", True),
    (AARCH64_EPILOGUE, "stack", False),
    (AARCH64_EPILOGUE, "leave", False),
    (AARCH64_EPILOGUE, "mov", False),
    (AARCH64_EPILOGUE, "call", False),
    (AARCH64_EPILOGUE, "branch", False),
    ("ldr x0, [sp, #8] ; ret", "pop", True),
    ("ldrb w2, [sp, #3] ; ret", "pop", True),
    ("add sp, sp, #0x10 ; ret", "stack", True),
    ("add sp, sp, #0x10 ; ret", "pop", False),
    ("mov sp, x29 ; ldp x29, x30, [sp], #0x10 ; ret", "leave", True),
    ("mov sp, x29 ; ldp x29, x30, [sp], #0x10 ; ret", "stack", True),
    ("mov x0, x1 ; ret", "mov", True),
    ("bl #0x1040 ; ret", "call", True),
    ("bl #0x1040 ; ret", "branch", False),
    ("blr x8", "call", True),
    ("blr x8", "branch", False),
    ("br x16", "branch", True),
    ("br x16", "call", False),
    ("b.eq #0x1044 ; ret", "branch", True),
    ("cbz x0, #0x1074 ; ret", "branch", True),
    ("mrs x0, nzcv ; eret ; ret", "branch", False),
]


class CategoryTest(unittest.TestCase):
    def setUp(self):
        self.x86_view = FakeView(image("c3"), arch_name="x86_64")
        self.aarch64_view = FakeView(words("c0035fd6"))

    def test_x86_categories(self):
        for text, category, expected in X86_CATEGORIES:
            with self.subTest(text=text, category=category):
                self.assertEqual(
                    matches_gadget_category(self.x86_view, text, category), expected
                )

    def test_aarch64_categories(self):
        for text, category, expected in AARCH64_CATEGORIES:
            with self.subTest(text=text, category=category):
                self.assertEqual(
                    matches_gadget_category(self.aarch64_view, text, category), expected
                )

    def test_categories_follow_the_view_architecture(self):
        self.assertTrue(matches_gadget_category(self.aarch64_view, AARCH64_EPILOGUE, "pop"))
        self.assertFalse(matches_gadget_category(self.x86_view, AARCH64_EPILOGUE, "pop"))
        self.assertTrue(matches_gadget_category(self.x86_view, "pop rdi ; ret", "pop"))
        self.assertFalse(matches_gadget_category(self.aarch64_view, "leave ; ret", "leave"))

    def test_unknown_view_uses_x86_categories(self):
        self.assertTrue(matches_gadget_category(None, "pop rdi ; ret", "pop"))

    def test_uncategorized_filter_keeps_everything(self):
        self.assertTrue(matches_gadget_category(self.aarch64_view, "ret", "all"))
        self.assertTrue(matches_gadget_category(self.x86_view, "ret", "all"))


class DisplayRowTest(unittest.TestCase):
    def setUp(self):
        self.view = FakeView(words("1f2003d5", "c0035fd6", "1f2003d5", "c0035fd6"))

    def test_finder_returns_relative_addresses(self):
        self.assertEqual(
            gadgets_for(self.view),
            {0x1000: "nop ; ret", 0x1004: "ret", 0x1008: "nop ; ret", 0x100c: "ret"},
        )

    def test_rows_are_deduplicated_sorted_and_absolute(self):
        gadgets = find_rop_gadgets_in_view(self.view)
        self.assertEqual(set(gadgets), {0, 4, 8, 12})

        deduplicated = format_gadget_rows_for_display(self.view, gadgets, deduplicate=True)
        self.assertEqual(
            [(row.address, row.text) for row in deduplicated],
            [(0x1000, "nop ; ret"), (0x1004, "ret")],
        )
        self.assertEqual(
            "".join(text for _, text in deduplicated[0].fragments), "nop ; ret"
        )

        all_rows = format_gadget_rows_for_display(self.view, gadgets, deduplicate=False)
        self.assertEqual(
            [row.address for row in all_rows], [0x1000, 0x1004, 0x1008, 0x100c]
        )


if __name__ == "__main__":
    unittest.main()
