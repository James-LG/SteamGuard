import unittest

from .context import steamguard
from steamguard import guard_code


class GuardCodeTest(unittest.TestCase):
    def test_get_code(self):
        self.assertEqual(guard_code.get_code("1234567890ABCDEFGHIJKLMNOPab=", 1570662828), "R5FGF")

if __name__ == "__main__":
    unittest.main()
