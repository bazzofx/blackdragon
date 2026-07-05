import os
import sys
import unittest

# Add parent directory to python path to resolve module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from generateTLSReport import SamuraiReportParser

class TestTLSReportParser(unittest.TestCase):
    def setUp(self):
        # Locate report templates in the same folder as this test script
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.samurai_report_path = os.path.abspath(os.path.join(self.script_dir, 'rawTLSReport.html'))
        self.nec_report_path = os.path.abspath(os.path.join(self.script_dir, 'tls1_falsePositiveReport.html'))

    def test_samurai_report_parsing(self):
        """Test that TLSv1 and TLSv1.1 are correctly parsed as supported and vulnerable when offered."""
        self.assertTrue(os.path.exists(self.samurai_report_path), f"File not found: {self.samurai_report_path}")
        with open(self.samurai_report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = SamuraiReportParser(content)
        findings = parser.get_summary()
        
        # In rawTLSReport.html, TLSv1 and TLSv1.1 are supported and vulnerable
        self.assertIn('TLSv1', findings['protocols']['supported'])
        self.assertIn('TLSv1.1', findings['protocols']['supported'])
        self.assertIn('TLSv1', findings['protocols']['vulnerable'])
        self.assertIn('TLSv1.1', findings['protocols']['vulnerable'])
        
        # TLSv1.2 and TLSv1.3 are also supported
        self.assertIn('TLSv1.2', findings['protocols']['supported'])
        self.assertIn('TLSv1.3', findings['protocols']['supported'])

    def test_nec_report_parsing(self):
        """Test that TLSv1 and TLSv1.1 are NOT parsed as supported or vulnerable when they are disabled (not offered)."""
        self.assertTrue(os.path.exists(self.nec_report_path), f"File not found: {self.nec_report_path}")
        with open(self.nec_report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = SamuraiReportParser(content)
        findings = parser.get_summary()
        
        # In tls1_falsePositiveReport.html, TLSv1 and TLSv1.1 are disabled and must not be marked as supported or vulnerable
        self.assertNotIn('TLSv1', findings['protocols']['supported'])
        self.assertNotIn('TLSv1.1', findings['protocols']['supported'])
        self.assertNotIn('TLSv1', findings['protocols']['vulnerable'])
        self.assertNotIn('TLSv1.1', findings['protocols']['vulnerable'])
        
        # TLSv1.2 and TLSv1.3 are supported
        self.assertIn('TLSv1.2', findings['protocols']['supported'])
        self.assertIn('TLSv1.3', findings['protocols']['supported'])

if __name__ == '__main__':
    unittest.main()
