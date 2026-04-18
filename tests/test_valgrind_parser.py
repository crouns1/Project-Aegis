import unittest

from aegis.parsers.valgrind_parser import parse_valgrind_trace


SAMPLE_TRACE = """
==123== Memcheck, a memory error detector
==123== Invalid read of size 4
==123== Invalid write of size 1
==123== Invalid write of size 8
==123== FILE DESCRIPTORS: 6 open (3 std) at exit.
==123== LEAK SUMMARY:
==123==    definitely lost: 1,024 bytes in 4 blocks
==123==    indirectly lost: 256 bytes in 2 blocks
==123== ERROR SUMMARY: 3 errors from 3 contexts (suppressed: 0 from 0)
"""


class TestValgrindParser(unittest.TestCase):
    def test_extracts_key_fields(self) -> None:
        findings = parse_valgrind_trace(SAMPLE_TRACE)
        self.assertEqual(findings.definitely_lost_bytes, 1024)
        self.assertEqual(findings.definitely_lost_blocks, 4)
        self.assertEqual(findings.indirectly_lost_bytes, 256)
        self.assertEqual(findings.indirectly_lost_blocks, 2)
        self.assertEqual(findings.invalid_read_events, 1)
        self.assertEqual(findings.invalid_write_events, 2)
        self.assertEqual(findings.total_invalid_access_events, 3)
        self.assertEqual(findings.open_fds_at_exit, 6)
        self.assertEqual(findings.std_fds_at_exit, 3)
        self.assertEqual(findings.unclosed_fds, 3)
        self.assertEqual(findings.error_summary_total, 3)
        self.assertEqual(findings.error_summary_contexts, 3)

    def test_fd_fallback_when_summary_missing(self) -> None:
        trace = """
==111== Open file descriptor 0: /dev/pts/0
==111== Open file descriptor 1: /dev/pts/0
==111== Open file descriptor 2: /dev/pts/0
==111== Open file descriptor 5: /tmp/demo.txt
"""
        findings = parse_valgrind_trace(trace)
        self.assertEqual(findings.open_fds_at_exit, 4)
        self.assertEqual(findings.std_fds_at_exit, 3)
        self.assertEqual(findings.unclosed_fds, 1)


if __name__ == "__main__":
    unittest.main()
