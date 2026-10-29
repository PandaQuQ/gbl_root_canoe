#!/usr/bin/env python3
"""Call-site mod/ref evidence for the ABL STRB slice; DOES NOT approve patching.
Analyzes direct call targets via conservative intraprocedural summaries.
An unknown pointer store, nested call, or indirect branch is NOT a proof of non-alias.
"""
import argparse,collections,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from strb_trace import load_inst,successors,mem,reg
TARGET=re.compile(r'0x([0-9a-f]+)\s*<',re.I)
def direct_target(ins):
 m=TARGET.search(' '.join(ins.args));return int(m.group(1),16) if m else None

def summarize(ins,start,cap=20000):
 todo=collections.deque([start]);seen=set(); hazards=set();stores=[];calls=[];returns=0
 while todo and len(seen)<cap:
  pc=todo.popleft()
  if pc in seen or pc not in ins: continue
  seen.add(pc);i=ins[pc];op=i.op
  if op.startswith(('str','stur','stp','stnp','stlr','stxr','cas','swp')):
   mm=next((mem(x) for x in i.args if mem(x) is not None),None)
   if mm and mm[0]=='sp':stores.append([hex(pc),mm[1]])
   else:hazards.add('POINTER_WRITE_MAY_ALIAS')
  if op in ('bl','blr'):
   calls.append(hex(pc));hazards.add('NESTED_CALL_UNSUMMARIZED')
  if op in ('br','blr'):hazards.add('INDIRECT_CONTROL')
  if op=='ret':returns+=1;continue
  if op in ('br','eret','brk','udf'):continue
  for n in successors(pc,i):
   if n is not None and n in ins:todo.append(n)
 if todo:hazards.add('SUMMARY_BUDGET_EXHAUSTED')
 if returns==0:hazards.add('NO_RETURN_OBSERVED')
 # Callee SP isn't caller SP, even direct SP stores here cannot be interpreted as caller-slot writes.
 return {'entry':hex(start),'instructions':len(seen),'returns':returns,
         'callee_sp_stores':stores[:20], 'nested_calls':calls[:20],
         'hazards':sorted(hazards),'proves_no_caller_sp_alias':False}

def report(path,start=0x17e30,end=0x191f0):
 ins=load_inst(path)
 # CFG intersection: reachable from spill AND able to reach reload.
 def reach(seed,edges):
  q=collections.deque([seed]);seen=set()
  while q:
   x=q.popleft()
   if x in seen or x not in ins:continue
   seen.add(x);q.extend(edges.get(x,()))
  return seen
 edges={pc:tuple(n for n in successors(pc,i) if n in ins) for pc,i in ins.items()}
 reverse=collections.defaultdict(list)
 for pc,ns in edges.items():
  for n in ns:reverse[n].append(pc)
 forward=reach(start,edges); backward=reach(end,reverse)
 relevant=forward & backward
 calls=[]
 for pc in sorted(p for p in relevant if start<p<end):
  i=ins[pc]
  if i.op not in ('bl','blr'):continue
  tgt=direct_target(i) if i.op=='bl' else None
  calls.append({'site':hex(pc),'op':i.op,'target':hex(tgt) if tgt is not None else None,
                'summary':summarize(ins,tgt) if tgt in ins else None})
 return {'image':str(path),'spill':hex(start),'reload':hex(end),
         'cfg_intersection_call_sites':len(calls),'reachable_in_graph':len(forward),'can_reach_reload':len(backward),'calls':calls,
         'note':'Call sites lie on a syntactic CFG path from spill to reload; branch conditions and pointer aliasing remain unproven. Do not approve EFI patching.',
         'patch_authorized':False}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('efi');p.add_argument('--out');a=p.parse_args()
 d=report(a.efi);s=json.dumps(d,indent=2)
 if a.out:Path(a.out).write_text(s+'\n')
 else:print(s)
