import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from call_effects import summarize
from strb_trace import Inst
class CallEffectsTests(unittest.TestCase):
    def test_safe_leaf(self):
        r=summarize({0:Inst('nop',()),4:Inst('ret',())},0)
        self.assertEqual(r['hazards'],[])
        self.assertEqual(r['returns'],1)
        self.assertFalse(r['proves_no_caller_sp_alias'])
    def test_unknown_store(self):
        r=summarize({0:Inst('str',('x0','[x1]')),4:Inst('ret',())},0)
        self.assertIn('POINTER_WRITE_MAY_ALIAS',r['hazards'])
    def test_nested_call(self):
        r=summarize({0:Inst('bl',('0x100 <fn>',)),4:Inst('ret',())},0)
        self.assertIn('NESTED_CALL_UNSUMMARIZED',r['hazards'])
    def test_budget(self):
        r=summarize({0:Inst('nop',()),4:Inst('nop',()),8:Inst('ret',())},0,cap=1)
        self.assertIn('SUMMARY_BUDGET_EXHAUSTED',r['hazards'])
if __name__=='__main__':unittest.main()
