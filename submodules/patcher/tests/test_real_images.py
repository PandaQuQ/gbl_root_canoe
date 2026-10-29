"""Optional real EFI regression tests. Set EFI_A, EFI_B, PATCHER_BIN env vars."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
BASE=Path(__file__).resolve().parents[1]
class RealImageTests(unittest.TestCase):
    def test_a_and_b_not_approved(self):
        for name in ('EFI_A','EFI_B'):
            path=os.environ.get(name)
            if not path:self.skipTest('requires EFI_A and EFI_B')
            with self.subTest(slot=name):
                with tempfile.TemporaryDirectory() as d:
                    cmd=[sys.executable,str(BASE/'tools/safe_build.py'),path,'--out',d]
                    if os.environ.get('PATCHER_BIN'):cmd.extend(['--patcher',os.environ['PATCHER_BIN']])
                    p=subprocess.run(cmd,capture_output=True,text=True)
                    self.assertIn(p.returncode,(0,2),p.stderr)
                    reports=list(Path(d).glob('*_diagnostic.json'))
                    self.assertEqual(len(reports),1)
                    report=json.loads(reports[0].read_text())
                    self.assertFalse(report['flashable'])
                    self.assertFalse(report['ready_to_install'])
                    self.assertFalse(report['analysis']['patch_authorized'])
                    self.assertGreater(report['analysis']['candidate_paths'],0)
                    self.assertEqual(report['analysis']['candidate_offsets'],['0x19214'])
                    self.assertFalse(list(Path(d).glob('*.efi')))
                    if os.environ.get('PATCHER_BIN'):
                        self.assertNotEqual(report['patcher']['exit_code'],0)
                        self.assertFalse(report['patcher']['staged_output_created'])
if __name__=='__main__':unittest.main()
