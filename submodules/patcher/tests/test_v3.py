import importlib.util
import unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'tools/strb_trace.py'
spec=importlib.util.spec_from_file_location('strb_trace',p)
m=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=m
spec.loader.exec_module(m)
I=lambda op,*args:m.Inst(op,args)

class TestCFG(unittest.TestCase):
    def demo(self,pre=None,mid=None,post=None):
        # the four key operations, plus optional instructions to model hazards.
        ins={0:I('ldrb','w21','[x23, #0xc95]'),
             4:I('mov','w9','w21'),
             8:I('str','x21','[sp, #0x20]'),
             12:I('nop'),
             16:I('ldp','x11','x10','[sp, #0x20]'),
             20:I('strb','w11','[sp, #0x60]')}
        if mid:ins[12]=mid
        if pre:ins[4]=pre
        if post:ins[16]=post
        return ins
    def test_direct_chain(self):
        r=m.inspect(self.demo(),0,20)
        self.assertEqual(r['candidate_paths'],1)
        self.assertFalse(r['patch_authorized'])
        self.assertEqual(r['example_paths'][0]['events'][0][0],'spill')
    def test_reg_clobber_before_spill(self):
        r=m.inspect(self.demo(pre=I('mov','w21','wzr')),0,20)
        self.assertEqual(r['candidate_paths'],0)
    def test_direct_stack_overwrite(self):
        r=m.inspect(self.demo(mid=I('str','xzr','[sp, #0x20]')),0,20)
        self.assertEqual(r['candidate_paths'],0)
    def test_no_overlap_stack_write(self):
        r=m.inspect(self.demo(mid=I('str','xzr','[sp, #0x30]')),0,20)
        self.assertEqual(r['candidate_paths'],1)
    def test_unknown_alias_write(self):
        r=m.inspect(self.demo(mid=I('str','xzr','[x22, #0x20]')),0,20)
        self.assertEqual(r['candidate_paths'],1)
        self.assertIn('UNKNOWN_ALIAS_STORE',r['example_paths'][0]['flags'])
        self.assertFalse(r['patch_authorized'])
    def test_known_alias_no_overlap(self):
        ins=self.demo()
        ins[4]=I('add','x22','sp','#0x80')
        ins[12]=I('str','xzr','[x22, #0x20]')
        r=m.inspect(ins,0,20)
        self.assertEqual(r['candidate_paths'],1)
        self.assertNotIn('UNKNOWN_ALIAS_STORE',r['example_paths'][0]['flags'])
    def test_known_alias_overwrite(self):
        ins=self.demo();ins[4]=I('add','x22','sp','#0x0');ins[12]=I('str','xzr','[x22, #0x20]')
        self.assertEqual(m.inspect(ins,0,20)['candidate_paths'],0)
    def test_call_preserves_callee_saved_but_is_uncertain(self):
        r=m.inspect(self.demo(mid=I('bl','0x100 <callee>')),0,20)
        self.assertEqual(r['candidate_paths'],1)
        self.assertIn('CALL_SIDE_EFFECT',r['example_paths'][0]['flags'])
    def test_stack_pointer_escapes_call(self):
        ins=self.demo();ins[4]=I('add','x0','sp','#0x20');ins[12]=I('bl','0x100 <callee>')
        r=m.inspect(ins,0,20)
        self.assertIn('STACK_PTR_CALL_ESCAPE',r['example_paths'][0]['flags'])
    def test_unknown_opcode_not_flash_approved(self):
        r=m.inspect(self.demo(mid=I('fake_sve_op','x20','x21')),0,20)
        self.assertEqual(r['candidate_paths'],1)
        self.assertFalse(r['patch_authorized'])
    def test_return_ends_path(self):
        self.assertEqual(m.inspect(self.demo(mid=I('ret')),0,20)['candidate_paths'],0)
    def test_auto_discovers_sink_without_offset(self):
        r=m.inspect(self.demo(),0,sink=None,anchor=15)
        self.assertEqual(r['candidate_offsets'],['0x14'])
        self.assertFalse(r['patch_authorized'])
    def test_conditional_branch_skips_register_clobber(self):
        ins=self.demo()
        ins[4]=I('cbz','w0','0x8 <spill>')
        # branch and fallthrough reach the same store, candidate is not duplicated
        self.assertEqual(m.inspect(ins,0,20)['candidate_offsets'],['0x14'])
    def test_missing_source_fails(self):
        with self.assertRaises(ValueError):m.inspect({20:I('strb','w11','[sp, #0x60]')},0,20)
    def test_widest_reg_kill(self):
        ins=self.demo(mid=I('ldp','x11','x10','[sp, #0x20]'),post=I('mov','w11','wzr'))
        self.assertEqual(m.inspect(ins,0,20)['candidate_paths'],0)
    def test_succs_branch(self):
        ins=I('cbz','w0','0x40 <label>')
        self.assertEqual(m.successors(20,ins),(24,64))

if __name__=='__main__':unittest.main()
