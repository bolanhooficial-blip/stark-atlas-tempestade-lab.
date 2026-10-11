"""STARK SPDA Core 0.8.0 — evidence reconciliation engine.

Classifies calculation chains by evidence quality, reconciles compatible
independent evidence, blocks incompatible evidence, and creates an exact
engineer-confirmation queue. Historical Golden Case only; not normative ABNT.
"""
from __future__ import annotations
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
import json, re

from stark_core import canonical_hash, D, decimal_str
from stark_provenance import WorkbookCellIndex, build_provenance_report, BEFORE, AFTER
from stark_zones import load_zone_snapshot, reconstruct_before, source_quantity_audit, compare_project_signatures, compute_relevant_quantities

RECONCILE_ENGINE_VERSION = "0.8.0"

ERROR_TOKENS = {"#DIV/0!", "#REF!", "#VALUE!", "#NAME?", "#N/A", "#NUM!", "#NULL!"}
GRADE_SCORE = {"A":100, "B":85, "C":65, "D":35, "E":0}


def _walk(trace: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    yield trace
    for d in trace.get("dependencies", []) or []:
        yield from _walk(d)


def _q(node: Mapping[str,Any]) -> str:
    return str(node.get("qualified") or f"{node.get('sheet')}!{node.get('cell')}")


def classify_chain(trace: Mapping[str,Any], source_breaks: Iterable[Mapping[str,Any]]=()) -> Dict[str,Any]:
    """Classify one trace without pretending that manual source inputs are defects."""
    break_keys={f"{x['sheet']}!{x['cell']}":x for x in source_breaks}
    nodes=list(_walk(trace))
    errors=[]; cycles=[]; maxdepth=[]; derived_breaks=[]; manual_leaves=[]; formula_nodes=[]
    for n in nodes:
        q=_q(n); val=n.get('value'); status=n.get('status'); formula=n.get('formula')
        if val in ERROR_TOKENS or (isinstance(val,str) and val.startswith('#')):
            errors.append(q)
        if status=='CYCLE': cycles.append(q)
        if status=='MAX_DEPTH': maxdepth.append(q)
        if q in break_keys: derived_breaks.append({"qualified":q,**break_keys[q]})
        if formula: formula_nodes.append(q)
        elif status=='SOURCE_LITERAL' and q not in break_keys:
            manual_leaves.append(q)
    if errors or cycles or maxdepth:
        grade='E'; cls='BROKEN_CHAIN'; complete=False
    elif derived_breaks:
        grade='C'; cls='TRACEABLE_WITH_BROKEN_DERIVATION'; complete=False
    elif trace.get('formula'):
        grade='A'; cls='COMPLETE_DERIVED_CHAIN'; complete=True
    else:
        grade='B'; cls='MANUAL_SOURCE_VALUE'; complete=True
    out={
        "classification":cls,"grade":grade,"score":GRADE_SCORE[grade],"complete":complete,
        "root":_q(trace),"root_value":trace.get('value'),"formula_nodes":formula_nodes,
        "manual_source_leaves":manual_leaves,"broken_derived_nodes":derived_breaks,
        "formula_errors":errors,"cycles":cycles,"max_depth_nodes":maxdepth,
    }
    out['trace_hash']=canonical_hash(out); return out


def cell_evidence(index: WorkbookCellIndex, sheet: str, cell: str, breaks=()) -> Dict[str,Any]:
    trace=index.trace(sheet,cell,max_depth=30)
    c=classify_chain(trace,breaks)
    rec=index.get(sheet,cell)
    out={
      "kind":"WORKBOOK_CELL","sheet":sheet,"cell":cell,"qualified":f"{sheet}!{cell}",
      "value":rec.value,"formula":rec.formula,"source_file":rec.source_file,"source_sha256":rec.source_sha256,
      "chain":c,"trace_hash":trace.get('trace_hash')
    }
    out['evidence_hash']=canonical_hash(out); return out


def external_evidence(kind: str, label: str, value: Any, grade: str, source: Mapping[str,Any], details: Optional[Mapping[str,Any]]=None) -> Dict[str,Any]:
    out={"kind":kind,"label":label,"value":str(value),"grade":grade,"score":GRADE_SCORE[grade],"source":dict(source),"details":dict(details or {})}
    out['evidence_hash']=canonical_hash(out); return out


def _same_numeric(a: Any,b: Any,tol: Decimal=Decimal('0')) -> bool:
    try: return abs(D(a)-D(b))<=tol
    except Exception: return str(a).strip()==str(b).strip()


def reconcile_values(issue_id: str, subject: str, candidates: List[Mapping[str,Any]], *, tolerance: str='0', context_blockers: Optional[List[Mapping[str,Any]]]=None, resolution_hint: str='') -> Dict[str,Any]:
    vals=[c.get('value') for c in candidates]
    agree=bool(vals) and all(_same_numeric(vals[0],v,D(tolerance)) for v in vals[1:])
    blockers=list(context_blockers or [])
    if blockers:
        status='BLOCKED_CONTEXT_MISMATCH'; needs=True
    elif agree:
        minscore=min(int(c.get('score',c.get('chain',{}).get('score',0))) for c in candidates) if candidates else 0
        if minscore>=85: status='RECONCILED_STRONG'
        elif minscore>=65: status='RECONCILED_WITH_SOURCE_CAVEAT'
        else: status='RECONCILED_WEAK'
        needs=False
    else:
        status='CONFLICTING_EVIDENCE'; needs=True
    out={"issue_id":issue_id,"subject":subject,"status":status,"needs_engineer_confirmation":needs,
         "tolerance":tolerance,"candidates":candidates,"context_blockers":blockers,"resolution_hint":resolution_hint}
    out['trace_hash']=canonical_hash(out); return out


def _candidate_from_cell(ev: Mapping[str,Any], label: str, transform=None) -> Dict[str,Any]:
    val=ev['value']; val=transform(val) if transform else val
    return {"label":label,"value":str(val),"grade":ev['chain']['grade'],"score":ev['chain']['score'],
            "classification":ev['chain']['classification'],"evidence_ref":ev['qualified'],"evidence_hash":ev['evidence_hash']}


def _find_audit(audit: Mapping[str,Any], field: str) -> Mapping[str,Any]:
    return next(x for x in audit['checks'] if x['field']==field)


def build_reconciliation_report(workbook_path: str|Path, snapshot_path: str|Path) -> Dict[str,Any]:
    idx=WorkbookCellIndex(workbook_path)
    prov=build_provenance_report(workbook_path,snapshot_path)
    snap=load_zone_snapshot(snapshot_path)
    source_breaks=prov['source_formula_breaks']
    before_param=reconstruct_before(snap,True)
    equation_audit=source_quantity_audit(snap['before'])
    signatures=compare_project_signatures(snap)

    evidence={}
    # Core R1 before evidence: workbook cell + independent parametric reconstruction.
    evidence['R1_BEFORE_CELL']=cell_evidence(idx,BEFORE,'O298',source_breaks)
    evidence['R1_BEFORE_PARAMETRIC']=external_evidence(
        'PARAMETRIC_RECONSTRUCTION','Golden Case zone reconstruction',before_param['R1_x1e5'],'A',
        {"snapshot_id":snap['snapshot_id'],"source_sha256":snap['source']['sha256'],"mode":before_param['mode']},
        {"passed":before_param['passed'],"trace_hash":before_param['trace_hash']})

    # The after scenario has two contradictory statements.
    evidence['R1_AFTER_CACHED']=cell_evidence(idx,AFTER,'O283',source_breaks)
    after_narr=cell_evidence(idx,AFTER,'B291',source_breaks)
    m=re.search(r'R1\s*=\s*([0-9]+,[0-9]+)E-05',str(after_narr['value'] or ''))
    narrative_x1e5=(m.group(1).replace(',','.') if m else '')
    evidence['R1_AFTER_NARRATIVE']=external_evidence(
        'NARRATIVE_STATEMENT','Narrative R1 after protection',narrative_x1e5,'B',
        {"qualified":after_narr['qualified'],"source_sha256":idx.sha256},
        {"raw_text":after_narr['value'],"cell_evidence_hash":after_narr['evidence_hash']})

    # Literal breaks that can be independently reconciled from zone sums.
    for cell,label in [('N292','RB_TOTAL'),('N293','RV_TOTAL')]:
        evidence[label+'_CELL']=cell_evidence(idx,BEFORE,cell,source_breaks)
    evidence['RB_ZONE_SUM']=external_evidence('ZONE_SUM','RB sum of zone components',before_param['component_totals_x1e5']['RB'],'A',
        {"snapshot_id":snap['snapshot_id'],"source_sha256":snap['source']['sha256']},{"trace_hash":before_param['trace_hash']})
    evidence['RV_ZONE_SUM']=external_evidence('ZONE_SUM','RV sum of zone components',before_param['component_totals_x1e5']['RV'],'A',
        {"snapshot_id":snap['snapshot_id'],"source_sha256":snap['source']['sha256']},{"trace_hash":before_param['trace_hash']})

    # ADJ literal cells are supported by equation recomputation to workbook display precision.
    for cell,label,field in [('F255','ADJ_P','ADJ_P_m2'),('F258','ADJ_T','ADJ_T_m2'),('F267','NDJ_P','NDJ_P'),('F270','NDJ_T','NDJ_T')]:
        evidence[label+'_CELL']=cell_evidence(idx,BEFORE,cell,source_breaks)
        a=_find_audit(equation_audit,field)
        evidence[label+'_RECOMPUTE']=external_evidence('EQUATION_RECOMPUTE',f'{label} equation recompute',a['calculated_display'],'A',
            {"snapshot_id":snap['snapshot_id'],"source_sha256":snap['source']['sha256']},a)

    issues=[]
    issues.append(reconcile_values('RC-001','R1 before protection (x1e-5)',[
        {"label":"Workbook O298","value":evidence['R1_BEFORE_CELL']['value'],"grade":evidence['R1_BEFORE_CELL']['chain']['grade'],"score":evidence['R1_BEFORE_CELL']['chain']['score'],"classification":evidence['R1_BEFORE_CELL']['chain']['classification'],"evidence_ref":evidence['R1_BEFORE_CELL']['qualified'],"evidence_hash":evidence['R1_BEFORE_CELL']['evidence_hash']},
        {"label":"Parametric zone reconstruction","value":evidence['R1_BEFORE_PARAMETRIC']['value'],"grade":"A","score":100,"classification":"INDEPENDENT_PARAMETRIC_RECONSTRUCTION","evidence_ref":"golden_case_zone_snapshot_0_6.json","evidence_hash":evidence['R1_BEFORE_PARAMETRIC']['evidence_hash']},
    ], resolution_hint='No engineer action required for historical reproduction; source caveats remain documented.'))

    issues.append(reconcile_values('RC-002','RB component total (x1e-5)',[
        _candidate_from_cell(evidence['RB_TOTAL_CELL'],'Workbook N292'),
        {"label":"Sum of zones","value":evidence['RB_ZONE_SUM']['value'],"grade":"A","score":100,"classification":"INDEPENDENT_ZONE_SUM","evidence_ref":"zone reconstruction","evidence_hash":evidence['RB_ZONE_SUM']['evidence_hash']},
    ], tolerance='0.0005', resolution_hint='Missing formula in N292 is reconciled by the independent zone sum at workbook display precision.'))
    issues.append(reconcile_values('RC-003','RV component total (x1e-5)',[
        _candidate_from_cell(evidence['RV_TOTAL_CELL'],'Workbook N293'),
        {"label":"Sum of zones","value":evidence['RV_ZONE_SUM']['value'],"grade":"A","score":100,"classification":"INDEPENDENT_ZONE_SUM","evidence_ref":"zone reconstruction","evidence_hash":evidence['RV_ZONE_SUM']['evidence_hash']},
    ], tolerance='0.0005', resolution_hint='Missing formula in N293 is reconciled by the independent zone sum at workbook display precision.'))
    issues.append(reconcile_values('RC-004','ADJ/P collection area (m2)',[
        _candidate_from_cell(evidence['ADJ_P_CELL'],'Workbook F255'),
        {"label":"Equation recompute","value":evidence['ADJ_P_RECOMPUTE']['value'],"grade":"A","score":100,"classification":"EQUATION_RECOMPUTE","evidence_ref":"source_quantity_audit","evidence_hash":evidence['ADJ_P_RECOMPUTE']['evidence_hash']},
    ], tolerance='10', resolution_hint='Manual cached value is supported at historical workbook display precision.'))
    issues.append(reconcile_values('RC-005','ADJ/T collection area (m2)',[
        _candidate_from_cell(evidence['ADJ_T_CELL'],'Workbook F258'),
        {"label":"Equation recompute","value":evidence['ADJ_T_RECOMPUTE']['value'],"grade":"A","score":100,"classification":"EQUATION_RECOMPUTE","evidence_ref":"source_quantity_audit","evidence_hash":evidence['ADJ_T_RECOMPUTE']['evidence_hash']},
    ], tolerance='10', resolution_hint='Manual cached value is supported at historical workbook display precision.'))
    issues.append(reconcile_values('RC-006','NDJ/P event rate',[
        _candidate_from_cell(evidence['NDJ_P_CELL'],'Workbook F267'),
        {"label":"Equation recompute","value":evidence['NDJ_P_RECOMPUTE']['value'],"grade":"A","score":100,"classification":"EQUATION_RECOMPUTE","evidence_ref":"source_quantity_audit","evidence_hash":evidence['NDJ_P_RECOMPUTE']['evidence_hash']},
    ], tolerance='0.0001', resolution_hint='Régis must confirm whether 0.0234 is a deliberate/manual engineering input or whether the equation/inputs should govern.'))
    issues.append(reconcile_values('RC-007','NDJ/T event rate',[
        _candidate_from_cell(evidence['NDJ_T_CELL'],'Workbook F270'),
        {"label":"Equation recompute","value":evidence['NDJ_T_RECOMPUTE']['value'],"grade":"A","score":100,"classification":"EQUATION_RECOMPUTE","evidence_ref":"source_quantity_audit","evidence_hash":evidence['NDJ_T_RECOMPUTE']['evidence_hash']},
    ], tolerance='0.0001', resolution_hint='Régis must confirm whether 0.0234 is a deliberate/manual engineering input or whether the equation/inputs should govern.'))
    issues.append(reconcile_values('RC-008','R1 after protection (x1e-5)',[
        {"label":"Workbook cached O283","value":evidence['R1_AFTER_CACHED']['value'],"grade":evidence['R1_AFTER_CACHED']['chain']['grade'],"score":evidence['R1_AFTER_CACHED']['chain']['score'],"classification":evidence['R1_AFTER_CACHED']['chain']['classification'],"evidence_ref":evidence['R1_AFTER_CACHED']['qualified'],"evidence_hash":evidence['R1_AFTER_CACHED']['evidence_hash']},
        {"label":"Narrative B291","value":evidence['R1_AFTER_NARRATIVE']['value'],"grade":"B","score":85,"classification":"MANUAL_NARRATIVE_STATEMENT","evidence_ref":after_narr['qualified'],"evidence_hash":evidence['R1_AFTER_NARRATIVE']['evidence_hash']},
    ], context_blockers=signatures['findings'], resolution_hint='First confirm whether the Before and After sheets belong to the same physical project. Then confirm the correct after-protection R1 or provide a corrected workbook.'))

    # Create exact engineer queue only for unresolved issues, grouped to avoid duplicate questions.
    queue=[]
    unresolved={x['issue_id']:x for x in issues if x['needs_engineer_confirmation']}
    if signatures['findings']:
        queue.append({
          "confirmation_id":"REGIS-001","priority":"CRITICAL","blocks":["RC-008"],
          "question":"As folhas 'Antes Prot' e 'Após prot' pertencem ao mesmo projeto físico?",
          "evidence":{"before":{"NG":snap['before']['project_signature']['ng'],"dimensions_m":snap['before']['project_signature']['dimensions_m'],"zones":[z['name'] for z in snap['before']['project_signature']['zones']]},
                      "after":{"NG":snap['after']['project_signature']['ng'],"dimensions_m":snap['after']['project_signature']['dimensions_m'],"zones":[z['name'] for z in snap['after']['project_signature']['zones']]}},
          "required_answer":"Confirmar SIM/NÃO. Se SIM, indicar qual conjunto de NG/dimensões/zonas é o correto e fornecer a fonte corrigida. Se NÃO, identificar a qual projeto pertence cada folha.",
          "why_needed":"Sem uma assinatura física compatível, a comparação Antes × Após é tecnicamente inválida."
        })
    if 'RC-006' in unresolved or 'RC-007' in unresolved:
        queue.append({
          "confirmation_id":"REGIS-002","priority":"HIGH","blocks":[x for x in ['RC-006','RC-007'] if x in unresolved],
          "question":"Os valores NDJ/P = 0,0234 e NDJ/T = 0,0234 foram inseridos manualmente de forma deliberada ou deveriam resultar da equação indicada na planilha?",
          "evidence":{"stored":{"NDJ_P":evidence['NDJ_P_CELL']['value'],"NDJ_T":evidence['NDJ_T_CELL']['value']},
                      "equation_recompute":{"NDJ_P":evidence['NDJ_P_RECOMPUTE']['value'],"NDJ_T":evidence['NDJ_T_RECOMPUTE']['value']}},
          "required_answer":"Informar qual valor deve prevalecer e, se 0,0234 estiver correto, indicar a justificativa/origem do valor. Se a equação deve prevalecer, fornecer/corrigir os parâmetros ou a fórmula aplicável.",
          "why_needed":"Esses valores alimentam RU/RV e alteram o R1 reconstruído por equação."
        })
    if 'RC-008' in unresolved:
        queue.append({
          "confirmation_id":"REGIS-003","priority":"CRITICAL","blocks":["RC-008"],
          "depends_on":["REGIS-001"] if signatures['findings'] else [],
          "question":"Qual é o R1 correto após as medidas de proteção: o total armazenado O283 = 0 ou o valor declarado no texto B291 = 0,09 × 10^-5?",
          "evidence":{"cached_O283":evidence['R1_AFTER_CACHED']['value'],"narrative_B291_x1e5":evidence['R1_AFTER_NARRATIVE']['value'],"formula_errors":prov['after_trace'].get('dependencies',[])},
          "required_answer":"Fornecer o valor correto e, preferencialmente, uma planilha/memorial corrigido em que os componentes após proteção somem ao R1 confirmado.",
          "why_needed":"A fonte contém duas evidências incompatíveis e percentuais com #DIV/0!."
        })

    # Human-readable evidence matrix.
    matrix=[]
    for key,ev in evidence.items():
        if ev.get('kind')=='WORKBOOK_CELL':
            matrix.append({"evidence_id":key,"subject":ev['qualified'],"value":ev['value'],"grade":ev['chain']['grade'],"score":ev['chain']['score'],"classification":ev['chain']['classification'],"source_sha256":ev['source_sha256']})
        else:
            matrix.append({"evidence_id":key,"subject":ev.get('label'),"value":ev.get('value'),"grade":ev.get('grade'),"score":ev.get('score'),"classification":ev.get('kind'),"source":ev.get('source')})

    automatic=[x for x in issues if not x['needs_engineer_confirmation']]
    report={
      "engine":f"STARK_RECONCILE_{RECONCILE_ENGINE_VERSION}","scope":"HISTORICAL_GOLDEN_CASE_EVIDENCE_RECONCILIATION",
      "normative_authority":False,"source_sha256":idx.sha256,"evidence_matrix":matrix,"issues":issues,
      "automatic_reconciliations":[x['issue_id'] for x in automatic],"engineer_confirmation_queue":queue,
      "open_issue_ids":[x['issue_id'] for x in issues if x['needs_engineer_confirmation']],
      "status":"BLOCKED_PENDING_ENGINEER_CONFIRMATION" if queue else "RECONCILED",
      "limitations":["Historical source reconciliation only; not a validation of current ABNT normative content.","A high evidence score measures traceability/consistency, not engineering correctness or regulatory compliance."]
    }
    report['trace_hash']=canonical_hash(report); return report


def reconciliation_gate(report: Mapping[str,Any]) -> Dict[str,Any]:
    critical=[q for q in report.get('engineer_confirmation_queue',[]) if q.get('priority')=='CRITICAL']
    high=[q for q in report.get('engineer_confirmation_queue',[]) if q.get('priority')=='HIGH']
    if critical: status='BLOCKED_CRITICAL_CONFIRMATIONS'
    elif high: status='BLOCKED_ENGINEER_CONFIRMATIONS'
    else: status='PASS_RECONCILED'
    out={"gate":"GOLDEN_CASE_EVIDENCE_RECONCILIATION_0_8","status":status,
         "critical_confirmations":[q['confirmation_id'] for q in critical],"high_confirmations":[q['confirmation_id'] for q in high],
         "automatic_reconciliations":report.get('automatic_reconciliations',[]),"report_trace_hash":report.get('trace_hash')}
    out['trace_hash']=canonical_hash(out); return out
