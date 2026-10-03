# SPDX-License-Identifier: MPL-2.0
import unittest
from kernel_memory_inventory import parse_sections, parse_symbols


class InventoryTests(unittest.TestCase):
    def test_sections_use_decimal_sizes_and_addresses(self):
        result = parse_sections("kernel :\nsection size addr\n.text 32 2097152\n"
                                ".bss 1048576 2101248\nTotal 1048608\n")
        self.assertEqual(result[1]["bytes"], 1048576)
        self.assertEqual(result[0]["address"], 2097152)

    def test_symbols_ignore_code_and_sort_by_size(self):
        result = parse_symbols("buffer b 4096 128\nentry T 1024 4096\n"
                               "table B 8192 2048\nmissing U 0 0\n")
        self.assertEqual([s["name"] for s in result], ["table", "buffer"])

    def test_empty_inventory_is_not_success(self):
        with self.assertRaises(ValueError):
            parse_sections("not an object")


if __name__ == "__main__":
    unittest.main()
