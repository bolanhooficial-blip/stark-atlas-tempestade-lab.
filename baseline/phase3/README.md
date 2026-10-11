# FASE 3 — EXECUÇÃO CONTROLADA (LABORATÓRIO)

**Não é software homologado para projetos de engenharia.** A integração original não foi alterada e permanece livre para execução externa ao supervisor em ambientes não bloqueados.

Comece por `RELATORIO_FASE3.md` e `MANIFESTO_SHA256.json`.

## Organização

- `runtime/` — broker do ambiente isolado, worker e script Linux.
- `dependency_phase2/` — cópias de referência com 18 módulos Python e manifestos. Não são versões atualizadas dos motores originais.
- `tests/` — 43 casos sem duplicação.
- `proofs/` — logs de execução, incluindo regressão de 52/66/108 testes.

## Como reproduzir, em Linux compatível

Requer Python 3.13 e bibliotecas `PyMuPDF`, `cryptography` e dependências dos módulos, além de `unshare`, `mount`, `chroot`, `setpriv`, `prlimit`, user namespaces e permissões compatíveis com o host.

```bash
cd ECO_CONTROLE_EXECUCAO_FASE3_20261009
python -m unittest discover -s tests -p test_phase3.py -v
```

**Não use `root`/sudo ou bypass de namespaces como alternativa a uma falha de execução.** Se o ambiente não admitir isolamento, o fluxo precisa falhar fechado.

Os testes sintéticos demonstram controles dentro do domínio do broker; não garantem que outras aplicações com acesso aos componentes históricos não consigam chamá-los diretamente.

Integridade: execute `python VERIFY_MANIFEST.py` após extração do ZIP. O manifesto cobre os bytes do código, testes, provas e documentação (não inclui a si próprio).
