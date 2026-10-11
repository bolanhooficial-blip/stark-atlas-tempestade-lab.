"""STARK SPDA Core 0.7.0 — cell provenance and calculation-chain reconstruction.

This module audits the historical Régis workbook at the OOXML-cell level.
It is a provenance/reproduction engine, NOT a normative ABNT implementation.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
import hashlib, json, re, zipfile, xml.etree.ElementTree as ET

from stark_core import canonical_hash, D, decimal_str
from stark_zones import load_zone_snapshot, reconstruct_before, verify_snapshot_source

PROVENANCE_ENGINE_VERSION = "0.7.0"
NS = {"m":"http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r":"http://schemas.openxmlformats.org/officeDocument/2006/relationships"}

CELL_RE = re.compile(r"(?:(?:'([^']+)'|([A-Za-z0-9_ .-]+))!)?(\$?[A-Z]{1,3}\$?\d+)(?::(\$?[A-Z]{1,3}\$?\d+))?")


def file_sha256(path: str | Path) -> str:
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()


def _col_to_num(col: str) -> int:
    n=0
    for ch in col:
        if ch.isalpha(): n=n*26+(ord(ch.upper())-64)
    return n


def _num_to_col(n: int) -> str:
    s=''
    while n:
        n,rem=divmod(n-1,26); s=chr(65+rem)+s
    return s


def _split_cell(ref: str) -> Tuple[int,int]:
    ref=ref.replace('$','')
    m=re.fullmatch(r'([A-Z]{1,3})(\d+)',ref)
    if not m: raise ValueError(ref)
    return int(m.group(2)), _col_to_num(m.group(1))


def expand_range(a: str,b: str) -> List[str]:
    r1,c1=_split_cell(a); r2,c2=_split_cell(b)
    out=[]
    for r in range(min(r1,r2),max(r1,r2)+1):
        for c in range(min(c1,c2),max(c1,c2)+1): out.append(f"{_num_to_col(c)}{r}")
    return out


@dataclass(frozen=True)
class CellRecord:
    sheet: str
    cell: str
    value: Any
    formula: Optional[str]
    cell_type: Optional[str]
    source_file: str
    source_sha256: str

    @property
    def qualified(self) -> str: return f"{self.sheet}!{self.cell}"


class WorkbookCellIndex:
    def __init__(self,path: str | Path):
        self.path=str(path); self.sha256=file_sha256(path); self.cells: Dict[Tuple[str,str],CellRecord]={}
        self.sheet_names: List[str]=[]; self._parse()

    def _parse(self):
        with zipfile.ZipFile(self.path) as z:
            shared=[]
            if 'xl/sharedStrings.xml' in z.namelist():
                root=ET.fromstring(z.read('xl/sharedStrings.xml'))
                for si in root.findall('m:si',NS):
                    shared.append(''.join((t.text or '') for t in si.iter('{%s}t'%NS['m'])))
            wb=ET.fromstring(z.read('xl/workbook.xml'))
            rels=ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
            relmap={r.attrib['Id']:r.attrib['Target'] for r in rels}
            for s in wb.find('m:sheets',NS):
                name=s.attrib['name']; rid=s.attrib['{%s}id'%NS['r']]
                target=relmap[rid].lstrip('/')
                if not target.startswith('xl/'): target='xl/'+target
                self.sheet_names.append(name)
                root=ET.fromstring(z.read(target))
                for c in root.findall('.//m:sheetData/m:row/m:c',NS):
                    ref=c.attrib['r'].replace('$',''); typ=c.attrib.get('t')
                    f=c.find('m:f',NS); v=c.find('m:v',NS); raw=v.text if v is not None else None
                    if typ=='s' and raw is not None:
                        try: val=shared[int(raw)]
                        except Exception: val=raw
                    elif typ=='inlineStr':
                        isel=c.find('m:is',NS); val=''.join((t.text or '') for t in isel.iter('{%s}t'%NS['m'])) if isel is not None else ''
                    else: val=raw
                    self.cells[(name,ref)]=CellRecord(name,ref,val,f.text if f is not None else None,typ,Path(self.path).name,self.sha256)

    def get(self,sheet: str,cell: str) -> CellRecord:
        key=(sheet,cell.replace('$',''))
        if key not in self.cells:
            return CellRecord(sheet,cell.replace('$',''),None,None,None,Path(self.path).name,self.sha256)
        return self.cells[key]

    def dependencies(self,sheet: str,formula: Optional[str]) -> List[Tuple[str,str]]:
        if not formula: return []
        out=[]; seen=set()
        for m in CELL_RE.finditer(formula):
            sh=m.group(1) or m.group(2) or sheet
            a=m.group(3).replace('$',''); b=m.group(4).replace('$','') if m.group(4) else None
            refs=expand_range(a,b) if b else [a]
            for ref in refs:
                k=(sh,ref)
                if k not in seen: out.append(k); seen.add(k)
        return out

    def trace(self,sheet: str,cell: str,max_depth: int=20,_stack: Optional[Tuple[Tuple[str,str],...]]=None) -> Dict[str,Any]:
        _stack=_stack or tuple(); key=(sheet,cell.replace('$','')); rec=self.get(*key)
        node={"sheet":sheet,"cell":rec.cell,"qualified":rec.qualified,"value":rec.value,"formula":rec.formula,
              "source_file":rec.source_file,"source_sha256":rec.source_sha256}
        if key in _stack:
            node.update({"status":"CYCLE","dependencies":[]}); return node
        if max_depth<=0:
            node.update({"status":"MAX_DEPTH","dependencies":[]}); return node
        deps=self.dependencies(sheet,rec.formula)
        if not deps:
            node.update({"status":"SOURCE_LITERAL" if rec.formula is None else "FORMULA_NO_CELL_REFS","dependencies":[]})
        else:
            node.update({"status":"FORMULA","dependencies":[self.trace(sh,rf,max_depth-1,_stack+(key,)) for sh,rf in deps]})
        node['trace_hash']=canonical_hash({k:v for k,v in node.items() if k!='trace_hash'})
        return node

    def export_snapshot(self,include_sheets: Optional[Iterable[str]]=None) -> Dict[str,Any]:
        allow=set(include_sheets or self.sheet_names)
        rows=[]
        for (sh,cell),rec in sorted(self.cells.items()):
            if sh in allow and (rec.value is not None or rec.formula is not None): rows.append(asdict(rec))
        payload={"engine":f"STARK_PROVENANCE_{PROVENANCE_ENGINE_VERSION}","source_file":Path(self.path).name,"source_sha256":self.sha256,"cells":rows}
        payload['trace_hash']=canonical_hash(payload); return payload


BEFORE='MEMORIAL DE CÁLCULO Antes Prot'; AFTER='MEMORIAL DE CÁLCULO Após prot'

# Semantic bindings for the audited historical workbook. These bindings describe
# workbook meaning; they are not normative constants.
SEMANTIC = {
    (BEFORE,'O298'):{'logical':'R1','kind':'RISK_TOTAL'},
    (BEFORE,'N290'):{'logical':'RA','kind':'COMPONENT_TOTAL'},(BEFORE,'N291'):{'logical':'RU','kind':'COMPONENT_TOTAL'},
    (BEFORE,'N292'):{'logical':'RB','kind':'COMPONENT_TOTAL'},(BEFORE,'N293'):{'logical':'RV','kind':'COMPONENT_TOTAL'},
    (BEFORE,'N294'):{'logical':'RC','kind':'COMPONENT_TOTAL'},(BEFORE,'N295'):{'logical':'RM','kind':'COMPONENT_TOTAL'},
    (BEFORE,'N296'):{'logical':'RW','kind':'COMPONENT_TOTAL'},(BEFORE,'N297'):{'logical':'RZ','kind':'COMPONENT_TOTAL'},
    (BEFORE,'H290'):{'logical':'RA_Z2','kind':'ZONE_COMPONENT'},(BEFORE,'H291'):{'logical':'RU_Z2','kind':'ZONE_COMPONENT'},
    (BEFORE,'H292'):{'logical':'RB_Z2','kind':'ZONE_COMPONENT'},(BEFORE,'H293'):{'logical':'RV_Z2','kind':'ZONE_COMPONENT'},
    (BEFORE,'N134'):{'logical':'LA_Z2','kind':'ZONE_LOSS'},(BEFORE,'N135'):{'logical':'LU_Z2','kind':'ZONE_LOSS'},
    (BEFORE,'N136'):{'logical':'LB_Z2','kind':'ZONE_LOSS'},(BEFORE,'N137'):{'logical':'LV_Z2','kind':'ZONE_LOSS'},
    (BEFORE,'N119'):{'logical':'rt_Z2','kind':'INPUT'},(BEFORE,'N120'):{'logical':'PTA_Z2','kind':'INPUT'},
    (BEFORE,'N121'):{'logical':'PTU_Z2','kind':'INPUT'},(BEFORE,'N122'):{'logical':'rf_Z2','kind':'INPUT'},
    (BEFORE,'N123'):{'logical':'rp_Z2','kind':'INPUT'},(BEFORE,'N129'):{'logical':'hz_Z2','kind':'INPUT'},
    (BEFORE,'N130'):{'logical':'LT_Z2','kind':'INPUT'},(BEFORE,'N131'):{'logical':'LF_Z2','kind':'INPUT'},
    (BEFORE,'N132'):{'logical':'LO_Z2','kind':'INPUT'},(BEFORE,'B110'):{'logical':'nz_Z2','kind':'INPUT'},
    (BEFORE,'B113'):{'logical':'nt_Z2','kind':'INPUT'},(BEFORE,'B116'):{'logical':'tz_Z2','kind':'INPUT'},
    (BEFORE,'F263'):{'logical':'ND','kind':'EVENT_RATE'},(BEFORE,'N49'):{'logical':'NG','kind':'INPUT'},
    (BEFORE,'F251'):{'logical':'AD','kind':'COLLECTION_AREA'},(BEFORE,'N55'):{'logical':'CD','kind':'INPUT'},
    (BEFORE,'N57'):{'logical':'PB','kind':'INPUT'},(BEFORE,'N58'):{'logical':'PEB','kind':'INPUT'},
    (BEFORE,'F265'):{'logical':'NL_P','kind':'EVENT_RATE'},(BEFORE,'F267'):{'logical':'NDJ_P','kind':'EVENT_RATE'},
    (BEFORE,'F268'):{'logical':'NL_T','kind':'EVENT_RATE'},(BEFORE,'F270'):{'logical':'NDJ_T','kind':'EVENT_RATE'},
    (AFTER,'O283'):{'logical':'R1_AFTER_CACHED','kind':'RISK_TOTAL'},(AFTER,'B291'):{'logical':'R1_AFTER_NARRATIVE','kind':'NARRATIVE'},
}

ZONE_ROWS={
 'Z2':{'component_col':'H','loss_rows':{'LA':134,'LU':135,'LB':136,'LV':137},'input_cells':{'nz':'B110','nt':'B113','tz':'B116','rt':'N119','PTA':'N120','PTU':'N121','rf':'N122','rp':'N123','hz':'N129','LT':'N130','LF':'N131','LO':'N132'}},
 'Z3':{'component_col':'I','loss_rows':{'LA':168,'LU':169,'LB':170,'LV':171},'input_cells':{'nz':'B144','nt':'B147','tz':'B150','rt':'N153','PTA':'N154','PTU':'N155','rf':'N156','rp':'N157','hz':'N163','LT':'N164','LF':'N165','LO':'N166'}},
 'Z4':{'component_col':'J','loss_rows':{'LA':202,'LU':203,'LB':204,'LV':205},'input_cells':{'nz':'B178','nt':'B181','tz':'B184','rt':'N187','PTA':'N188','PTU':'N189','rf':'N190','rp':'N191','hz':'N197','LT':'N198','LF':'N199','LO':'N200'}},
 'Z5':{'component_col':'K','loss_rows':{'LA':236,'LU':237,'LB':238,'LV':239},'input_cells':{'nz':'B212','nt':'B215','tz':'B218','rt':'N221','PTA':'N222','PTU':'N223','rf':'N224','rp':'N225','hz':'N231','LT':'N232','LF':'N233','LO':'N234'}},
}
COMPONENT_ROWS={'RA':290,'RU':291,'RB':292,'RV':293,'RC':294,'RM':295,'RW':296,'RZ':297}


def semantic_record(index: WorkbookCellIndex,sheet: str,cell: str) -> Dict[str,Any]:
    rec=index.get(sheet,cell); sem=SEMANTIC.get((sheet,cell),{})
    return {**asdict(rec),**sem,'dependencies':[f"{s}!{c}" for s,c in index.dependencies(sheet,rec.formula)]}


def build_ra_z2_lineage(index: WorkbookCellIndex) -> Dict[str,Any]:
    refs=[('R1','O298'),('RA','N290'),('RA_Z2','H290'),('ND','F263'),('PTA_Z2','N120'),('PB','N57'),('LA_Z2','N134'),
          ('rt_Z2','N119'),('LT_Z2','N130'),('nz_Z2','B110'),('nt_Z2','B113'),('tz_Z2','B116')]
    nodes=[]
    for logical,cell in refs:
        r=semantic_record(index,BEFORE,cell); r['logical']=logical; nodes.append(r)
    edges=[
      ['O298','N290','R1 includes RA'],['N290','H290','RA total includes Z2'],['H290','F263','RA_Z2 uses ND'],
      ['H290','N120','RA_Z2 uses PTA_Z2'],['H290','N57','RA_Z2 uses PB'],['H290','N134','RA_Z2 uses LA_Z2'],
      ['N134','N119','LA_Z2 uses rt'],['N134','N130','LA_Z2 uses LT'],['N134','B110','LA_Z2 uses nz'],
      ['N134','B113','LA_Z2 uses nt'],['N134','B116','LA_Z2 uses tz']]
    result={'engine':f'STARK_PROVENANCE_{PROVENANCE_ENGINE_VERSION}','chain_name':'R1_RA_Z2_LA_INPUTS','source_sha256':index.sha256,
            'nodes':nodes,'edges':[{'from':f'{BEFORE}!{a}','to':f'{BEFORE}!{b}','meaning':m} for a,b,m in edges]}
    result['trace_hash']=canonical_hash(result); return result


def _source_formula_breaks(index: WorkbookCellIndex) -> List[Dict[str,Any]]:
    expected={
      'N292':'SUM(G292:M292)','N293':'SUM(G293:M293)',
      'F255':'ADJ formula described in N255 but cached as literal','F258':'ADJ formula described in N258 but cached as literal',
      'F267':'NDJ/P equation described in N267 but cached as literal','F270':'NDJ/T equation described in N270 but cached as literal',
    }
    out=[]
    for cell,relation in expected.items():
        rec=index.get(BEFORE,cell)
        if not rec.formula:
            out.append({'code':'SOURCE_LITERAL_BREAK','sheet':BEFORE,'cell':cell,'value':rec.value,'expected_relation':relation,'severity':'MEDIUM'})
    return out


def _missing_formula_refs(trace: Mapping[str,Any]) -> List[str]:
    # Empty cells referenced inside Excel ranges are legitimate and are ignored by
    # SUM/MAX. A provenance failure is an explicit broken reference/cycle/depth
    # truncation, not an empty spreadsheet cell.
    missing=[]
    def walk(n):
        formula=n.get('formula') or ''
        if '#REF!' in formula or n.get('status') in {'CYCLE','MAX_DEPTH'}:
            missing.append(n['qualified'])
        for d in n.get('dependencies',[]): walk(d)
    walk(trace); return sorted(set(missing))


def build_provenance_report(workbook_path: str | Path,snapshot_path: str | Path) -> Dict[str,Any]:
    idx=WorkbookCellIndex(workbook_path); snap=load_zone_snapshot(snapshot_path)
    source_check=verify_snapshot_source(snap,str(workbook_path))
    parametric=reconstruct_before(snap,True)
    root=idx.trace(BEFORE,'O298',max_depth=20)
    after_root=idx.trace(AFTER,'O283',max_depth=12)
    lineage=build_ra_z2_lineage(idx)
    breaks=_source_formula_breaks(idx)
    missing=_missing_formula_refs(root)
    component_cells={cid:semantic_record(idx,BEFORE,f'N{row}') for cid,row in COMPONENT_ROWS.items()}
    zone_cells={}
    for zid,zdef in ZONE_ROWS.items():
        col=zdef['component_col']; zone_cells[zid]={}
        for cid,row in {'RA':290,'RU':291,'RB':292,'RV':293}.items(): zone_cells[zid][cid]=semantic_record(idx,BEFORE,f'{col}{row}')
        zone_cells[zid]['losses']={k:semantic_record(idx,BEFORE,f'N{r}') for k,r in zdef['loss_rows'].items()}
        zone_cells[zid]['inputs']={k:semantic_record(idx,BEFORE,c) for k,c in zdef['input_cells'].items()}
    checks=[]
    checks.append({'check':'SOURCE_HASH','passed':source_check['passed'],'detail':source_check['status']})
    checks.append({'check':'PARAMETRIC_R1_MATCH','passed':D(parametric['R1_x1e5'])==D(idx.get(BEFORE,'O298').value),'stark':parametric['R1_x1e5'],'source':idx.get(BEFORE,'O298').value})
    checks.append({'check':'R1_TRACE_NO_MISSING_REFS','passed':not missing,'missing':missing})
    checks.append({'check':'RA_Z2_LINEAGE','passed':all(n['value'] is not None for n in lineage['nodes'])})
    after_cached=idx.get(AFTER,'O283').value; narrative=idx.get(AFTER,'B291').value or ''
    checks.append({'check':'AFTER_SOURCE_INCONSISTENCY_RETAINED','passed':str(after_cached) in {'0','0.0'} and '0,09E-05' in narrative,'cached':after_cached,'narrative':narrative})
    status='PASS_BEFORE_PROVENANCE_WITH_DOCUMENTED_SOURCE_BREAKS_AFTER_BLOCKED' if all(c['passed'] for c in checks) else 'PROVENANCE_REVIEW_REQUIRED'
    result={'engine':f'STARK_PROVENANCE_{PROVENANCE_ENGINE_VERSION}','source_file':Path(workbook_path).name,'source_sha256':idx.sha256,
            'source_check':source_check,'before_parametric':parametric,'root_trace':root,'ra_z2_lineage':lineage,
            'component_cells':component_cells,'zone_cells':zone_cells,'source_formula_breaks':breaks,'checks':checks,
            'after_trace':after_root,'after_narrative_cell':semantic_record(idx,AFTER,'B291'),'status':status,
            'limitations':['Historical workbook reproduction only; not a current normative ABNT library.',
                           'Literal source cells are preserved as provenance endpoints and are not silently reverse-engineered into normative formulas.']}
    result['trace_hash']=canonical_hash({k:v for k,v in result.items() if k!='trace_hash'}); return result


def provenance_gate(report: Mapping[str,Any]) -> Dict[str,Any]:
    reasons=[]
    if report.get('status')!='PASS_BEFORE_PROVENANCE_WITH_DOCUMENTED_SOURCE_BREAKS_AFTER_BLOCKED': reasons.append('PROVENANCE_REPORT_NOT_PASSING')
    if not report.get('source_check',{}).get('passed'): reasons.append('SOURCE_HASH_MISMATCH')
    if report.get('after_narrative_cell',{}).get('value') is None: reasons.append('AFTER_NARRATIVE_MISSING')
    status='PASS_BEFORE_PROVENANCE_AFTER_BLOCKED' if not reasons else 'BLOCKED'
    out={'gate':'GOLDEN_CASE_CELL_PROVENANCE_0_7','status':status,'reasons':reasons,
         'documented_source_breaks':report.get('source_formula_breaks',[]),'report_trace_hash':report.get('trace_hash')}
    out['trace_hash']=canonical_hash(out); return out
