#!/usr/bin/env python3
"""Offline STRB build gate. Never installs, flashes, or authorizes boot images.

Usage: python tools/safe_build.py ORIGINAL_EFI [--patcher PATCHER] [--out DIR]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from strb_trace import load_inst,inspect,compare_patches

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('original_efi',type=Path)
    p.add_argument('--patcher',type=Path)
    p.add_argument('--out',type=Path,default=Path('reports'))
    p.add_argument('--source',type=lambda x:int(x,0),default=0x17b20)
    p.add_argument('--sink',type=lambda x:int(x,0),default=None)
    args=p.parse_args()
    original=args.original_efi.resolve()
    if not original.is_file():p.error('original EFI not found')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    inst=load_inst(original)
    analysis=inspect(inst,args.source,args.sink)
    analysis['image_sha256']=hashlib.sha256(original.read_bytes()).hexdigest()
    report={'build_gate':'FAIL_CLOSED','analysis':analysis,'patcher':None,
            'flashable':False,'ready_to_install':False}
    if args.patcher:
        exe=args.patcher.resolve()
        if not exe.is_file():p.error('patcher binary not found')
        with tempfile.TemporaryDirectory(prefix='strb_safe_build_') as d:
            temp_out=Path(d)/'unverified_output.efi'
            proc=subprocess.run([str(exe),str(original),str(temp_out)],text=True,
                                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            report['patcher']={'exit_code':proc.returncode,'log':proc.stdout,
                               'staged_output_created':temp_out.exists()}
            if temp_out.exists():
                report['patcher']['comparison']=compare_patches(original,temp_out)
                # Do not copy an unverified executable into a user-facing output dir.
    target=out/(original.stem+'_diagnostic.json')
    target.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('Report:',target)
    print('Candidates:',analysis['candidate_paths'],' | Analyzer confidence:',analysis['status'])
    print('Build authorization: DENIED (no validated boot image produced)')
    if report['patcher']:
        print('Patcher exit:',report['patcher']['exit_code'],
              '| staged output:',report['patcher']['staged_output_created'])
    return 0 if not report['patcher'] or report['patcher']['exit_code'] != 0 else 2
if __name__=='__main__':sys.exit(main())
