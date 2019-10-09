import pkgutil
import unittest

from .context import steamguard
from steamguard import guard_code


class GuardCodeTest(unittest.TestCase):
    def test_get_code(self):
        print(guard_code.get_code("1234567890ABCDEFGHIJKLMNOPab="))

if __name__ == "__main__":
    unittest.main()
