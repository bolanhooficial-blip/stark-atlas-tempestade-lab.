"""Phase 3: controlled laboratory broker with OS namespace isolation.

No public server. No operator-supplied Python or executable path. The only
entry point is this trusted host-side broker. It does NOT change old modules.
No SPDA calculations or executive releases are available. Deploying this next
to unrestricted original modules does NOT prevent bypass outside this broker.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Mapping
import fcntl
import threading
from functools import wraps
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time



ROOT=Path(__file__).resolve().parent
PHASE2=ROOT.parent/'dependency_phase2'
ALLOWED=frozenset({'CLASSIFY_STARK','EXPORT_ATLAS_DRAFT','SPDA_CALCULATE','EXECUTIVE_RELEASE','ISOLATION_PROBE'})
DOC_PATTERN=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
SUPPORTED=frozenset({'.pdf','.json','.txt','.csv','.dxf','.xlsx','.png'})

class Blocked(RuntimeError):pass


def jdump(data)->bytes:
    return json.dumps(data,sort_keys=True,ensure_ascii=False,
                      separators=(',',':'),allow_nan=False).encode('utf-8')


def sha(data:bytes)->str:return sha256(data).hexdigest()


def _secure_store(store:Path):
    if store.is_symlink():raise Blocked('STATE_DIR_SYMLINK')
    store=store.resolve()
    store.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(store,0o700)
    return store




def synchronized(method):
    """One-file process lock + reentrant per-instance thread guard.
    Covers DB transaction plus nontransactional signed anchor update.
    """
    @wraps(method)
    def impl(self,*a,**kw):
        with self._thread_lock:
            first=self._lock_depth==0
            if first:fcntl.flock(self._lock_fd,fcntl.LOCK_EX)
            self._lock_depth+=1
            try:return method(self,*a,**kw)
            finally:
                self._lock_depth-=1
                if first:fcntl.flock(self._lock_fd,fcntl.LOCK_UN)
    return impl

@dataclass(frozen=True)
class ExecutionResult:
    state:str
    run_key:str
    details:dict
    artifact_pdf:bytes|None=None
    artifact_png:bytes|None=None


class DurableLedger:
    """Atomic single-node SQLite + separately held HMAC key/chain anchor.
    HMAC is for detection of DB-only tampering, NOT an external WORM audit.
    The key & anchor cannot be made secure against the same host administrator.
    """
    def __init__(self,folder:Path):
        self.folder=_secure_store(folder)
        self.db=self.folder/'phase3.sqlite3'
        self._thread_lock=threading.RLock()
        self._lock_depth=0
        self._lock_fd=os.open(str(self.folder/'ledger.lock'),os.O_RDWR|os.O_CREAT,0o600)
        self.key_file=self.folder/'audit_hmac_key.private'
        self.anchor_file=self.folder/'audit_anchor.private'
        if not self.key_file.exists():
            fd=os.open(str(self.key_file),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as f:f.write(os.urandom(32));f.flush();os.fsync(f.fileno())
        if self.key_file.stat().st_mode & 0o077:raise Blocked('INSECURE_AUDIT_KEY_PERMISSIONS')
        self.key=self.key_file.read_bytes()
        if len(self.key)!=32:raise Blocked('AUDIT_KEY_INVALID')
        self.cx=sqlite3.connect(str(self.db),timeout=30,isolation_level=None,check_same_thread=False)
        self.cx.execute('PRAGMA journal_mode=DELETE')
        self.cx.execute('PRAGMA synchronous=FULL')
        self.cx.execute('PRAGMA busy_timeout=30000')
        self.cx.execute('CREATE TABLE IF NOT EXISTS runs (run_key TEXT PRIMARY KEY, project_id TEXT NOT NULL, revision TEXT NOT NULL, operation TEXT NOT NULL, state TEXT NOT NULL, created_ns INTEGER NOT NULL, details TEXT NOT NULL)')
        self.cx.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_key TEXT NOT NULL, event TEXT NOT NULL, prev_mac TEXT NOT NULL, mac TEXT NOT NULL)')
        if not self.anchor_file.exists():
            existing=self.cx.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            if existing:raise Blocked('MISSING_ANCHOR_WITH_EXISTING_RECORDS')
            self._anchor('GENESIS')
        self.validate()

    def _anchor(self,m):
        tmp=self.anchor_file.with_suffix('.temp')
        fd=os.open(str(tmp),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(m);f.flush();os.fsync(f.fileno())
        os.replace(tmp,self.anchor_file)

    @staticmethod
    def _row_hash(row):
        return sha(jdump({'run_key':row[0],'project_id':row[1],
            'revision':row[2],'operation':row[3],
            'state':row[4],'created_ns':row[5],
            'details':json.loads(row[6])}))

    @synchronized
    def validate(self):
        try:
            state=self.cx.execute('PRAGMA integrity_check').fetchone()[0]
            if state!='ok':raise Blocked('DATABASE_INTEGRITY_FAILED')
            prev='GENESIS'
            latest={}
            for rid,key,event,linked,mac in self.cx.execute('SELECT id,run_key,event,prev_mac,mac FROM events ORDER BY id'):
                expected=hmac.new(self.key,jdump({'id':rid,'run_key':key,'event':event,'prev_mac':prev}),hashlib.sha256).hexdigest()
                if linked!=prev or not hmac.compare_digest(mac,expected):raise Blocked('AUDIT_CHAIN_MODIFIED')
                prev=mac
                latest[key]=event
            rows=list(self.cx.execute('SELECT run_key,project_id,revision,operation,state,created_ns,details FROM runs'))
            if set(latest)!={x[0] for x in rows}:raise Blocked('AUDIT_RUN_SET_MISMATCH')
            for row in rows:
                expected_prefix=('CLAIMED' if row[4]=='RUNNING' else 'RESULT:'+row[4])
                if latest[row[0]]!=expected_prefix+':'+self._row_hash(row):
                    raise Blocked('AUDIT_RUN_MODIFIED')
            if self.anchor_file.read_text()!=prev:raise Blocked('AUDIT_ANCHOR_MISMATCH')
        except (OSError,sqlite3.Error) as exc:
            raise Blocked('AUDIT_STORE_UNAVAILABLE') from exc

    def _append(self,key:str,event:str):
        previous=self.cx.execute('SELECT mac FROM events ORDER BY id DESC LIMIT 1').fetchone()
        prev=previous[0] if previous else 'GENESIS'
        id_next=self.cx.execute('SELECT IFNULL(MAX(id),0)+1 FROM events').fetchone()[0]
        mac=hmac.new(self.key,jdump({'id':id_next,'run_key':key,'event':event,'prev_mac':prev}),hashlib.sha256).hexdigest()
        self.cx.execute('INSERT INTO events(id,run_key,event,prev_mac,mac) VALUES (?,?,?,?,?)',(id_next,key,event,prev,mac))
        return mac

    @synchronized
    def claim(self,run_key:str,project_id:str,revision:str,operation:str)->bool:
        self.validate()
        self.cx.execute('BEGIN IMMEDIATE')
        try:
            if self.cx.execute('SELECT 1 FROM runs WHERE run_key=?',(run_key,)).fetchone():
                self.cx.execute('ROLLBACK');return False
            self.cx.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,?)',
                (run_key,project_id,revision,operation,'RUNNING',time.time_ns(),'{}'))
            row=self.cx.execute('SELECT * FROM runs WHERE run_key=?',(run_key,)).fetchone()
            new_mac=self._append(run_key,'CLAIMED:'+self._row_hash(row))
            self.cx.execute('COMMIT')
            self._anchor(new_mac)
            return True
        except Exception:
            self.cx.execute('ROLLBACK');raise

    @synchronized
    def complete(self,run_key:str,state:str,details:dict):
        self.validate()
        if state not in {'EVIDENCE_ONLY','DRAFT_REVIEW_REQUIRED','BLOCKED'}:
            raise Blocked('INVALID_TERMINAL_STATE')
        self.cx.execute('BEGIN IMMEDIATE')
        try:
            old=self.cx.execute('SELECT state FROM runs WHERE run_key=?',(run_key,)).fetchone()
            if old is None or old[0]!='RUNNING':raise Blocked('RUN_STATE_NOT_PENDING')
            self.cx.execute('UPDATE runs SET state=?,details=? WHERE run_key=?',
                (state,jdump(details).decode(),run_key))
            row=self.cx.execute('SELECT * FROM runs WHERE run_key=?',(run_key,)).fetchone()
            new_mac=self._append(run_key,'RESULT:'+state+':'+self._row_hash(row))
            self.cx.execute('COMMIT')
            self._anchor(new_mac)
        except Exception:
            self.cx.execute('ROLLBACK');raise

    @synchronized
    def report(self,run_key:str)->dict|None:
        self.validate()
        row=self.cx.execute('SELECT project_id,revision,operation,state,details FROM runs WHERE run_key=?',(run_key,)).fetchone()
        if row is None:return None
        return dict(zip(('project_id','revision','operation','state','details'),(*row[:4],json.loads(row[4]))))

    def close(self):
        self.cx.close()
        os.close(self._lock_fd)


class MandatoryBroker:
    """L3 gate is mandatory FOR THIS CONTROLLED EXECUTION DOMAIN ONLY.

    Requires OS user+mount+network namespaces, chroot filesystem whitelist,
    a fixed worker image and a durable broker ledger. No fallback mode.
    """
    def __init__(self,state_dir:Path,phase2:Path=PHASE2,*,test_probes:bool=False):
        self.state_dir=_secure_store(Path(state_dir))
        self.phase2=Path(phase2).resolve()
        self.test_probes=test_probes
        self._verify_vendor()
        self.ledger=DurableLedger(self.state_dir)

    def _verify_vendor(self):
        known=json.loads((self.phase2/'VENDOR_BASELINE_HASHES.json').read_text())
        files=[p for p in (self.phase2/'vendor_snapshots').iterdir() if p.is_file() or p.is_symlink()]
        if {f.name for f in files}!={k for k in known} or not files:
            raise Blocked('VENDOR_SET_CHANGED')
        for item in files:
            if item.is_symlink() or not item.is_file():raise Blocked('VENDOR_NONREGULAR')
            if sha(item.read_bytes())!=known[item.name]['sha256']:raise Blocked('VENDOR_DRIFT')
        self.vendor_hash=sha(jdump({k:v['sha256'] for k,v in known.items()}))
        phase2_manifest=json.loads((self.phase2/'MANIFESTO_DA_ENTREGA.json').read_text())
        manifest_entry=next((x for x in phase2_manifest['files'] if x['path']=='pilot_runtime.py'),None)
        if manifest_entry is None or sha((self.phase2/'pilot_runtime.py').read_bytes())!=manifest_entry['sha256']:
            raise Blocked('PHASE2_HOST_DRIFT')
        self.pilot_hash=manifest_entry['sha256']

    def _validate(self,op:str,env:dict,paths:Mapping[str,Path],params:dict):
        if op not in ALLOWED:raise Blocked('OPERATION_NOT_ALLOWED')
        if op=='ISOLATION_PROBE' and not self.test_probes:raise Blocked('PROBES_NOT_ENABLED')
        if not isinstance(env,dict) or not isinstance(params,dict):raise Blocked('INVALID_REQUEST_SHAPE')
        if op=='CLASSIFY_STARK' and env.get('engine')!='STARK':raise Blocked('ENGINE_ROUTE_MISMATCH')
        if op=='EXPORT_ATLAS_DRAFT' and env.get('engine')!='ATLAS':raise Blocked('ENGINE_ROUTE_MISMATCH')
        if op in {'EXECUTIVE_RELEASE','SPDA_CALCULATE'}:raise Blocked('NO_QUALIFIED_EXECUTIVE_SPDA')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',str(env.get('project_id',''))):
            raise Blocked('UNSAFE_PROJECT_ID')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',str(env.get('revision',''))):
            raise Blocked('UNSAFE_REVISION_ID')
        from dataclasses import fields
        import sys
        sys.path.insert(0,str(self.phase2/'vendor_snapshots'))
        from security_boundary import Envelope,Source,verify_source_set
        try:
            if set(env)!={f.name for f in fields(Envelope)}:raise Blocked('ENVELOPE_FIELDS_UNEXPECTED')
            sources=tuple(Source(**s) for s in env['sources'])
            frozen=Envelope(**dict(env,sources=sources,required_controls=tuple(env['required_controls'])))
            frozen.validate()
        except (TypeError,KeyError,ValueError) as exc:raise Blocked('ENVELOPE_INVALID') from exc
        except Exception as exc:raise Blocked('ENVELOPE_REJECTED') from exc
        doc_ids=[s.doc_id for s in sources]
        if not all(DOC_PATTERN.fullmatch(x) for x in doc_ids):raise Blocked('UNSAFE_DOCUMENT_ID')
        if set(paths)!=set(doc_ids):raise Blocked('DOCUMENT_SET_MISMATCH')
        if op in {'CLASSIFY_STARK','EXPORT_ATLAS_DRAFT'}:
            if set(params)-({'doc_id'} if op=='CLASSIFY_STARK' else {'doc_id','bbox','geometry_payload','dimension_payload','page_number','dpi'}):
                raise Blocked('UNEXPECTED_OPERATION_PARAMETERS')
            if params.get('doc_id') not in doc_ids:raise Blocked('DOCUMENT_NOT_IN_ENVELOPE')
        if op=='EXPORT_ATLAS_DRAFT':
            if not isinstance(params.get('geometry_payload'),dict) or not isinstance(params.get('dimension_payload'),dict):
                raise Blocked('GEOMETRY_PAYLOAD_REQUIRED')
            if not isinstance(params.get('dpi',72),int) or not 36<=params.get('dpi',72)<=150:
                raise Blocked('DPI_OUT_OF_BOUNDS')
            if not isinstance(params.get('page_number',1),int) or not 1<=params.get('page_number',1)<=100:
                raise Blocked('PAGE_OUT_OF_BOUNDS')
            if params.get('bbox') is not None:
                rect=params['bbox']
                if not isinstance(rect,(list,tuple)) or len(rect)!=4 or not all(isinstance(x,(int,float)) and not isinstance(x,bool) and abs(x)<100000 for x in rect):
                    raise Blocked('INVALID_BBOX')
        if len(jdump(params))>30000:raise Blocked('EXCESSIVE_OPERATION_PARAMS')
        for doc_id,path in paths.items():
            if not Path(path).suffix.lower() in SUPPORTED:raise Blocked('UNSUPPORTED_FORMAT')
        try:
            sources_bytes=verify_source_set(frozen,{k:Path(v) for k,v in paths.items()})
        except Exception as exc:
            raise Blocked('SOURCE_INTEGRITY_OR_ACCESS_REJECTED') from exc
        return frozen,sources_bytes

    def execute(self,op:str,envelope:dict,source_paths:Mapping[str,Path],params:dict|None=None,
                *,timeout:int=30)->ExecutionResult:
        params={} if params is None else params
        if not 2<=timeout<=60:raise Blocked('INVALID_TIMEOUT')
        self._verify_vendor()
        env,data=self._validate(op,envelope,source_paths,params)
        extensions={k:Path(v).suffix.lower() for k,v in source_paths.items()}
        key=sha(jdump({'operation':op,'envelope':env.content(),'params':params,
                       'vendor_hash':self.vendor_hash,'pilot_hash':self.pilot_hash,
                       'worker_sha256':sha((ROOT/'worker.py').read_bytes()),
                       'namespace_script_sha256':sha((ROOT/'namespace_entry.sh').read_bytes())}))
        if not self.ledger.claim(key,env.project_id,env.revision,op):
            raise Blocked('DUPLICATE_OR_INTERRUPTED_RUN')
        result=None
        try:
            result=self._spawn_isolated(op,env.content(),data,extensions,params,timeout)
            self.ledger.complete(key,result.state,dict(result.details))
            return ExecutionResult(result.state,key,result.details,result.artifact_pdf,result.artifact_png)
        except Exception as exc:
            self.ledger.complete(key,'BLOCKED',{'reason':type(exc).__name__,
                                                'message':str(exc)[:90] if isinstance(exc,Blocked) else 'ISOLATED_WORKER_FAILED'})
            raise

    def _spawn_isolated(self,op,env,data,extensions,params,timeout):
        # Stage root is world-traversable only during execution and contains
        # nothing except explicitly selected evidence, nonsecret code, outputs.
        with tempfile.TemporaryDirectory(prefix='eco-f3-sbox-') as td:
            root=Path(td)/'root'
            import secrets
            isolated_uid=200000+secrets.randbelow(100000)
            for d in ['app','app/input','app/vendor_snapshots','out','tmp','dev','usr','lib','lib64','opt/pyvenv']:
                (root/d).mkdir(parents=True,exist_ok=True)
            for device in ['null','urandom','zero']:
                (root/'dev'/device).touch()
            os.chown(td,isolated_uid,isolated_uid)
            Path(td).chmod(0o700)
            os.chown(root,isolated_uid,isolated_uid)
            root.chmod(0o700)
            os.chown(root/'out',isolated_uid,isolated_uid)
            (root/'out').chmod(0o700)
            (root/'tmp').chmod(0o777)
            (root/'app').chmod(0o755)
            (root/'app/input').chmod(0o755)
            for src,dst in [(ROOT/'worker.py',root/'app/worker.py'),
                            (self.phase2/'pilot_runtime.py',root/'app/pilot_runtime.py')]:
                shutil.copyfile(src,dst);dst.chmod(0o444)
            for src in sorted((self.phase2/'vendor_snapshots').glob('*.py')):
                dst=root/'app/vendor_snapshots'/src.name
                shutil.copyfile(src,dst);dst.chmod(0o444)
            for doc_id,content in data.items():
                target=root/'app/input'/f'{doc_id}-{sha(content)[:16]}{extensions[doc_id]}'
                target.write_bytes(content);target.chmod(0o444)
            request={'operation':op,'envelope':env,'params':params,
                     'extensions':extensions,'probe_enabled':self.test_probes}
            (root/'app/request.json').write_bytes(jdump(request));(root/'app/request.json').chmod(0o444)
            # Inline the fixed trusted mount/chroot script so that staging works even
            # when the install folder is private and inaccessible to worker UID.
            sandbox_script=(ROOT/'namespace_entry.sh').read_text(encoding='utf-8')
            cmd=['/usr/bin/prlimit','--as=2147483648','--fsize=31457280','--nofile=128','--cpu=40',
                 '/usr/bin/setpriv','--reuid',str(isolated_uid),'--regid',str(isolated_uid),'--clear-groups','--no-new-privs',
                 '/usr/bin/unshare','-Urmpni','--fork','--kill-child=SIGKILL',
                 '/bin/sh','-c',sandbox_script,'eco-f3-entry',str(root)]
            try:
                proc=subprocess.run(cmd,capture_output=True,timeout=timeout,check=False,
                    env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C.UTF-8'},
                    start_new_session=True)
            except (OSError,subprocess.TimeoutExpired) as exc:
                raise Blocked('NAMESPACE_LAUNCH_FAILED_OR_TIMED_OUT') from exc
            out=root/'out/result.json'
            if proc.returncode!=0 or not out.is_file() or out.stat().st_size>200000:
                # Do not return stdout/host paths as a result to a client.
                raise Blocked('SANDBOX_FAILURE')
            msg=json.loads(out.read_text(encoding='utf-8'))
            if set(msg)-{'status','payload','audit_count','reason','code'}:
                raise Blocked('WORKER_RESPONSE_SCHEMA_INVALID')
            if msg.get('status')=='BLOCKED':
                return ExecutionResult('BLOCKED','',{'code':msg.get('code','GATE_BLOCKED')})
            if msg.get('status') not in {'EVIDENCE_ONLY','DRAFT_REVIEW_REQUIRED'}:
                raise Blocked('WORKER_RESPONSE_STATE_INVALID')
            payload=msg.get('payload')
            if not isinstance(payload,dict) or not payload:raise Blocked('WORKER_RESPONSE_EMPTY')
            pdf=png=None
            if op=='EXPORT_ATLAS_DRAFT':
                pdf_path=root/'out/draft.pdf';png_path=root/'out/draft.png'
                if (not pdf_path.is_file() or not png_path.is_file() or
                    pdf_path.stat().st_size>25_000_000 or png_path.stat().st_size>25_000_000):
                    raise Blocked('DERIVATIVE_SIZE_OR_TYPE_INVALID')
                pdf=pdf_path.read_bytes();png=png_path.read_bytes()
                if (len(pdf)>25_000_000 or len(png)>25_000_000 or not pdf.startswith(b'%PDF-') or
                    not png.startswith(b'\x89PNG\r\n\x1a\n') or sha(pdf)!=payload.get('pdf_sha256') or sha(png)!=payload.get('png_sha256')):
                    raise Blocked('DERIVATIVE_HASH_OR_FORMAT_INVALID')
                if payload.get('status')!='DRAFT_REVIEW_REQUIRED':raise Blocked('DERIVATIVE_STATUS_INVALID')
            return ExecutionResult(msg['status'],'',{'payload':payload,'audit_count':msg.get('audit_count')},pdf,png)
