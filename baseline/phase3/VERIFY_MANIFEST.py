#!/usr/bin/env python3
"""Offline SHA256 manifest verification; no network or code execution of modules."""
from pathlib import Path
from hashlib import sha256
import json,sys
r=Path(__file__).resolve().parent
try:
 d=json.loads((r/'MANIFESTO_SHA256.json').read_text(encoding='utf-8'))
 listed={x['path'] for x in d['files']}
 actual={p.relative_to(r).as_posix() for p in r.rglob('*')
     if p.is_file() and not any(y in p.parts for y in ('__pycache__','.pytest_cache'))
     and p.name!='MANIFESTO_SHA256.json' and not p.name.endswith('.pyc')}
 if actual!=listed:raise ValueError('LISTA_ARQUIVOS_DIVERGENTE '+str(sorted(actual^listed)))
 for entry in d['files']:
  file=r/entry['path']
  if file.is_symlink():raise ValueError('SIMLINK_NAO_PERMITIDO: '+entry['path'])
  b=file.read_bytes()
  if len(b)!=entry['bytes'] or sha256(b).hexdigest()!=entry['sha256']:raise ValueError('HASH_DIVERGENTE: '+entry['path'])
 print('OK -',len(listed),'arquivos conferidos')
except Exception as e:
 print('BLOQUEADO:',str(e),file=sys.stderr);raise SystemExit(1)
