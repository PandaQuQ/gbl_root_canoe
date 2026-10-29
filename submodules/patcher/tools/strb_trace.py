#!/usr/bin/env python3
"""Read-only ARM64 STRB provenance explorer.

This is an *evidence finder*, not a formal proof of path feasibility, memory
non-aliasing or boot safety. It deliberately cannot authorize flashing.
Requires llvm-objdump. Does not patch input images.
"""
from __future__ import annotations
import argparse
import collections
import dataclasses
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

LINE = re.compile(r'^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+([a-z0-9_.]+)\s*(.*)$')
HEX_TARGET = re.compile(r'0x([0-9a-f]+)\s*<', re.I)
REG = re.compile(r'^[wx](\d+)$', re.I)
MEM = re.compile(r'^\[(sp|x\d+)(?:,\s*#(0x[0-9a-f]+|\d+))?\]$',re.I)

@dataclasses.dataclass(frozen=True)
class Inst:
    op: str
    args: tuple[str,...]

def split_args(text):
    parts=[]; depth=0; start=0
    for i,c in enumerate(text):
        if c=='[':depth+=1
        if c==']':depth-=1
        if c==',' and depth==0:
            parts.append(text[start:i].strip()); start=i+1
    parts.append(text[start:].strip())
    return tuple(parts)

def reg(s):
    m=REG.fullmatch(s.strip())
    return int(m[1]) if m else None

def mem(s):
    m=MEM.fullmatch(s.strip())
    return (m[1],int(m[2] or '0',0)) if m else None

def load_inst(image):
    exe=shutil.which('llvm-objdump')
    if not exe:raise RuntimeError('llvm-objdump not found')
    p=subprocess.run([exe,'-d',str(image)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    ins={}
    for ln in p.stdout.splitlines():
        m=LINE.match(ln)
        if m:ins[int(m[1],16)]=Inst(m[2],split_args(m[3].split('//')[0].strip()))
    return ins

def successors(pc, ins):
    op=ins.op
    if op in ('ret','eret','br','brk','udf'):return ()
    t=HEX_TARGET.search(' '.join(ins.args))
    target=int(t[1],16) if t else None
    if op=='b':return (target,) if target is not None else ()
    if op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz'):
        return (pc+4,target) if target is not None else (pc+4,)
    return (pc+4,)

def wbit(r):return 1<<r if r is not None and r < 31 else 0

def overlap(a,n,b,m):return a<b+m and b<a+n

# Keep small, auditable sets of hazards, not speculative "proof" claims.
HAZARDS = {
 'CALL_SIDE_EFFECT':1<<0,
 'INDIRECT_CALL':1<<1,
 'UNKNOWN_ALIAS_STORE':1<<2,
 'UNKNOWN_INSTRUCTION':1<<3,
 'SP_CHANGE':1<<4,
 'ALIAS_UNMODELLED':1<<5,
 'DATA_TRANSFORM':1<<6,
 'STACK_PTR_CALL_ESCAPE':1<<7,
}

@dataclasses.dataclass(frozen=True)
class State:
    pc:int
    regmask:int
    slotmask:int  # low eight bytes of [SP+#0x20]
    flags:int
    evidence:int # bits: source->spill, spill->reload
    aliases:tuple[int|None,...] # known SP-relative X-register pointers
    trace:tuple[tuple[str,str],...]

def step(s, ins, slot_offset):
    op=ins.op; a=ins.args; regs=s.regmask; stk=s.slotmask; flags=s.flags; ev=s.evidence
    aliases=list(s.aliases)
    def has(r):return bool(regs&wbit(r))
    def change(r,active):
        nonlocal regs
        b=wbit(r)
        regs=(regs|b) if active else (regs&~b)
    def write_stack(off,size,tainted):
        nonlocal stk
        for k in range(8):
            if overlap(off,size,slot_offset+k,1):
                if tainted:stk|=1<<k
                else:stk&=~(1<<k)
    def read_stack(off,size):
        return any(stk&(1<<k) and overlap(off,size,slot_offset+k,1) for k in range(8))
    def width(x):return 8 if x.startswith('x') else 4 if x.startswith('w') else 16 if x.startswith('q') else 0
    events=[]
    if op in ('str','stur','strb','strh','stp','stnp','stur','ldp','ldnp','ldr','ldur','ldrb','ldrh','ldrsw','ldrsb','ldurh') and a:
        paired=op in ('stp','ldp','stnp','ldnp')
        mm=mem(a[2] if paired and len(a)>2 else a[1] if len(a)>1 else '')
        eff=None
        if mm:
            if mm[0]=='sp':eff=mm[1]
            else:
                base=reg(mm[0])
                if base is not None and aliases[base] is not None:eff=aliases[base]+mm[1]
        r=reg(a[0]);r2=reg(a[1]) if paired else None
        sz=(1 if op.endswith('b') else 2 if op.endswith('h') else 4 if a[0].startswith('w') else 8 if a[0].startswith('x') else 16 if a[0].startswith('q') else 0)
        is_store=op.startswith(('str','stur','stp','stnp'))
        if eff is not None and sz:
            off=eff
            if is_store:
                write_stack(off,sz,has(r))
                if paired:write_stack(off+sz,sz,has(r2))
                if off==slot_offset and r==21 and has(r):
                    ev|=1;events.append(('spill',hex(off)))
            else:
                change(r,read_stack(off,sz))
                if paired:change(r2,read_stack(off+sz,sz))
                if paired and off==slot_offset and r==11 and has(11):
                    ev|=2;events.append(('reload',hex(off)))
        elif is_store:
            flags|=HAZARDS['UNKNOWN_ALIAS_STORE']
        elif r is not None:
            change(r,False)
            if paired:change(r2,False)
        if not is_store:
            if r is not None:aliases[r]=None
            if paired and r2 is not None:aliases[r2]=None
    elif op in ('mov','movz','movn','movk','orr','eor','and','add','sub','mul','madd','csel','csinc','csneg','csinv','adr','adrp','ubfx','sxtw','uxtw','lsr','lsl') and a:
        dst=reg(a[0]);val=(any(has(reg(x)) for x in a[1:] if reg(x) is not None))
        if a[0]=='sp':
            flags|=HAZARDS['SP_CHANGE']
            aliases=[None]*31
        if dst is not None:
            alias=None
            if op=='mov' and len(a)>1:
                if a[1]=='sp':alias=0
                elif reg(a[1]) is not None and a[1].startswith('x'):alias=aliases[reg(a[1])]
            elif op in ('add','sub') and len(a)>2 and a[0].startswith('x'):
                base=0 if a[1]=='sp' else (aliases[reg(a[1])] if reg(a[1]) is not None and a[1].startswith('x') else None)
                try:delta=int(a[2].replace('#',''),0)
                except ValueError:delta=None
                if base is not None and delta is not None:alias=base+(delta if op=='add' else -delta)
            aliases[dst]=alias
            if op in ('movz','movn','adr','adrp'):val=False
            elif op=='movk':val=val or has(dst)
            elif op not in ('mov','orr','add','sub','csel'):flags|=HAZARDS['DATA_TRANSFORM'] if val else 0
            change(dst,val)
    elif op in ('bl','blr'):
        # AAPCS64 preserves x19..x28; only known SP-relative argument pointers
        # are tracked, other pointer escapes remain an unproven assumption.
        if any(aliases[r] is not None for r in range(8)):
            flags|=HAZARDS['STACK_PTR_CALL_ESCAPE']
        for j in range(19):aliases[j]=None
        regs &= ~((1<<19)-1)
        flags|=HAZARDS['CALL_SIDE_EFFECT']
        if op=='blr': flags|=HAZARDS['INDIRECT_CALL']
    elif op in ('cmp','cmn','tst','nop','hint','bti','paciasp','autiasp','pacibsp','autibsp','ret','eret','br','b','cbz','cbnz','tbz','tbnz') or op.startswith('b.'):
        pass
    elif op in ('cset','cinc','csetm','cinv') and a:
        change(reg(a[0]),False)
    elif op.startswith(('ld','st')) and any('[' in x for x in a):
        flags|=HAZARDS['UNKNOWN_INSTRUCTION']|HAZARDS['ALIAS_UNMODELLED']
    else:
        # Unknown dest can be a register; treating it as killed is safer.
        if a and reg(a[0]) is not None:
            change(reg(a[0]),False)
            aliases[reg(a[0])]=None
        flags|=HAZARDS['UNKNOWN_INSTRUCTION']
    return regs,stk,flags,ev,tuple(aliases),tuple(events)

def inspect(ins, source=0x17b20,sink=None, slot_offset=0x20, source_reg=21, state_limit=250000, anchor=0x1918c):
    if source not in ins or (sink is not None and sink not in ins):raise ValueError('missing source/sink')
    expected_src=ins[source]
    expected_sink=ins[sink] if sink is not None else None
    if expected_src.op!='ldrb' or (expected_sink is not None and expected_sink.op!='strb'):
        raise ValueError('expected LDRB at source and STRB at sink')
    starts=[State(source+4,wbit(source_reg),0,0,0,(None,)*31,())]
    queue=collections.deque(starts);seen=set();hits=[];attempted=0;all_flags=0
    while queue and attempted<state_limit and len(hits)<12:
        s=queue.popleft();attempted+=1
        key=(s.pc,s.regmask,s.slotmask,s.flags,s.evidence,s.aliases)
        if key in seen or s.pc not in ins:continue
        seen.add(key);ii=ins[s.pc]
        is_sink = (s.pc==sink if sink is not None else (ii.op=='strb' and s.pc>anchor))
        if is_sink:
            if ii.op=='strb' and s.regmask&wbit(reg(ii.args[0])) and s.evidence==3:
                hits.append({'offset':hex(s.pc),
                   'flags':[x for x,b in HAZARDS.items() if s.flags&b],
                   'events':list(s.trace)+[('sink',hex(s.pc))]})
            if sink is not None:continue
        regs,slots,flags,ev,aliases,events=step(s,ii,slot_offset)
        all_flags |= flags
        tr=(s.trace+tuple(events))[-16:]
        for nxt in successors(s.pc,ii):
            if nxt is not None:
                queue.append(State(nxt,regs,slots,flags,ev,aliases,tr))
    return {
      'version':'v3_abi_aware_candidate', 'source':hex(source),'sink':hex(sink) if sink is not None else 'AUTO',
      'slot':hex(slot_offset),'source_instruction':f'{expected_src.op} {", ".join(expected_src.args)}',
      'sink_instruction':f'{expected_sink.op} {", ".join(expected_sink.args)}' if expected_sink is not None else 'auto-discovery',
      'states_processed':attempted,'unique_states':len(seen),
      'budget_exhausted':bool(queue), 'candidate_paths':len(hits), 'candidate_offsets':sorted(set(x['offset'] for x in hits)), 'example_paths':hits[:3],
      'warnings_encountered':[k for k,b in HAZARDS.items() if all_flags&b],
      'patch_authorized':False,
      'status':'CANDIDATE_NOT_PROOF' if hits else 'INCONCLUSIVE',
      'not_proven':['branch-condition satisfiability','complete stack pointer escape analysis',
                    'interprocedural memory mod/ref summaries','EFI runtime/verified boot compatibility']}

def compare_patches(original,patched,expected=None):
    a=Path(original).read_bytes();b=Path(patched).read_bytes()
    if len(a)!=len(b):raise ValueError('different file sizes')
    byte_diffs=[i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    spans=[]
    for i in byte_diffs:
        if not spans or i>spans[-1][-1]+1:spans.append([i])
        else:spans[-1].append(i)
    return {'original_sha256':hashlib.sha256(a).hexdigest(),
      'modified_sha256':hashlib.sha256(b).hexdigest(), 'bytes_changed':len(byte_diffs),
      'diff_spans':[{'start':hex(x[0]),'end_exclusive':hex(x[-1]+1),'count':len(x)} for x in spans],
      'patch_authorized':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('original_efi');p.add_argument('--patched');p.add_argument('--out')
    p.add_argument('--source',type=lambda s:int(s,0),default=0x17b20)
    p.add_argument('--sink',type=lambda s:int(s,0),default=None,help='Optional specific sink, otherwise discover STRB sinks')
    args=p.parse_args()
    ins=load_inst(args.original_efi)
    result=inspect(ins,args.source,args.sink)
    result['original_efi']=str(args.original_efi)
    result['instruction_count']=len(ins)
    if args.patched:result['binary_comparison']=compare_patches(args.original_efi,args.patched)
    out=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.out:Path(args.out).write_text(out,encoding='utf-8')
    else:print(out)
    # Do not use the exit code as a positive verification of flashability.
if __name__=='__main__':main()
