"""Static operation dispatcher. Runs ONLY in namespace+chroot. No arbitrary RPC.
This source is a reference pilot and must not be used for unsupervised SPDA.
"""
from __future__ import annotations
import base64
import json
import os
import sys
from dataclasses import fields
from pathlib import Path

sys.path.insert(0, '/app')
sys.path.insert(0, '/app/vendor_snapshots')
from security_boundary import Envelope,Source, GateBlocked,sha_bytes
from pilot_runtime import PilotRuntime

IN=Path('/app/request.json')
OUT=Path('/out/result.json')


def emit(obj:dict):
    tmp=OUT.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,allow_nan=False),encoding='utf-8')
    os.replace(tmp,OUT)


def read_env(obj):
    obj=dict(obj)
    obj['sources']=tuple(Source(**s) for s in obj['sources'])
    obj['required_controls']=tuple(obj['required_controls'])
    return Envelope(**obj)


def main():
    request=json.loads(IN.read_text(encoding='utf-8'))
    operation=request['operation']
    if operation not in {'CLASSIFY_STARK','EXPORT_ATLAS_DRAFT','SPDA_CALCULATE','EXECUTIVE_RELEASE','ISOLATION_PROBE'}:
        raise GateBlocked('UNAUTHORIZED_OPERATION')
    env=read_env(request['envelope'])
    source_paths={s.doc_id:Path('/app/input')/f'{s.doc_id}-{s.sha256[:16]}{request["extensions"][s.doc_id]}' for s in env.sources}
    with PilotRuntime(env,source_paths) as rt:
        if operation=='CLASSIFY_STARK':
            output={'type':'classification','data':rt.classify_stark_source(request['params']['doc_id'])}
        elif operation=='EXPORT_ATLAS_DRAFT':
            doc_id=request['params']['doc_id']
            if request['params'].get('bbox') is not None:
                bbox=tuple(request['params']['bbox'])
            else: bbox=None
            rt.bind_atlas(doc_id,geometry_payload=request['params']['geometry_payload'],
                dimension_payload=request['params']['dimension_payload'])
            result=rt.export_atlas_draft(doc_id,page_number=request['params'].get('page_number',1),
                bbox=bbox,dpi=request['params'].get('dpi',72))
            (Path('/out')/'draft.pdf').write_bytes(result.pdf)
            (Path('/out')/'draft.png').write_bytes(result.png)
            output={'type':'draft','status':result.status,'pdf_sha256':sha_bytes(result.pdf),
                    'png_sha256':sha_bytes(result.png),'manifest':dict(result.manifest)}
        elif operation=='SPDA_CALCULATE':rt.require_spda_execution()
        elif operation=='EXECUTIVE_RELEASE':rt.require_executive_release()
        elif operation=='ISOLATION_PROBE':
            # This probe can ONLY be enabled by a local test flag in the broker.
            if request.get('probe_enabled') is not True:raise GateBlocked('PROBE_DISABLED')
            import socket
            host_file='/mnt/data/KIMI_AUDITORIA_FONTES/stark_core.py'
            host_visible=Path(host_file).exists()
            root_visible=Path('/root').exists()
            try:
                socket.socket().connect(('127.0.0.1',9))
                net='CONNECTED'
            except OSError:
                net='BLOCKED'
            output={'type':'isolation_probe','host_file_visible':host_visible,
                'root_visible':root_visible,'network_loopback':net,
                'uid_inside':os.getuid()}
        emit({'status':'DRAFT_REVIEW_REQUIRED' if operation=='EXPORT_ATLAS_DRAFT' else 'EVIDENCE_ONLY',
              'payload':output,'audit_count':len(rt.audit_events())})

if __name__=='__main__':
    try:main()
    except Exception as exc:
        # No stack traces, host paths or exceptions returned to caller.
        emit({'status':'BLOCKED','reason':type(exc).__name__,
              'code':str(exc)[:100] if isinstance(exc,GateBlocked) else 'WORKER_FAILURE'})
