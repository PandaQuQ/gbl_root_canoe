"""Regression tests for conservative verification and source-target rejection."""
import importlib.util,sys,unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'tools/strb_trace.py'
spec=importlib.util.spec_from_file_location('strb_trace',p)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
I=lambda op,*a:m.Inst(op,a)

def chain(intermediate):
    return {0:I('ldrb','w21','[x23, #0xc95]'),4:I('str','x21','[sp, #0x20]'),
            8:intermediate,12:I('ldp','x11','x10','[sp, #0x20]'),
            16:I('strb','w11','[sp, #0x60]')}

class Guardrails(unittest.TestCase):
    def test_sink_must_be_strb(self):
        d=chain(I('nop'));d[16]=I('str','x11','[sp, #0x60]')
        with self.assertRaises(ValueError):m.inspect(d,0,16)
    def test_branch_bypassing_spill_not_accepted_without_evidence(self):
        d={0:I('ldrb','w21','[x23, #0xc95]'),4:I('b','0xc <reload>'),8:I('str','x21','[sp, #0x20]'),12:I('ldp','x11','x10','[sp, #0x20]'),16:I('strb','w11','[sp, #0x60]')}
        self.assertEqual(m.inspect(d,0,16)['candidate_paths'],0)
    def test_stack_partial_overwrite_kills_byte(self):
        self.assertEqual(m.inspect(chain(I('strb','wzr','[sp, #0x20]')),0,16)['candidate_paths'],1)
        # Other seven bytes are still marked; a byte-level sink requires a finer-grained proof.
        self.assertFalse(m.inspect(chain(I('strb','wzr','[sp, #0x20]')),0,16)['patch_authorized'])
    def test_unknown_indirect_store_never_authorized(self):
        r=m.inspect(chain(I('str','xzr','[x9, #0x20]')),0,16)
        self.assertIn('UNKNOWN_ALIAS_STORE',r['example_paths'][0]['flags'])
        self.assertFalse(r['patch_authorized'])
    def test_call_never_authorizes(self):
        r=m.inspect(chain(I('bl','0x100 <callee>')),0,16)
        self.assertIn('CALL_SIDE_EFFECT',r['example_paths'][0]['flags'])
        self.assertFalse(r['patch_authorized'])
    def test_missing_instruction_not_proof(self):
        d=chain(I('nop'));del d[12]
        self.assertEqual(m.inspect(d,0,16)['candidate_paths'],0)
    def test_unknown_sp_adjustment_is_hazard(self):
        r=m.inspect(chain(I('add','sp','sp','#0x10')),0,16)
        self.assertFalse(r['patch_authorized'])
    def test_register_zero_not_a_taint_source(self):
        d=chain(I('nop'));d[4]=I('str','xzr','[sp, #0x20]')
        self.assertEqual(m.inspect(d,0,16)['candidate_paths'],0)
if __name__=='__main__':unittest.main()
