# Revisão inicial e reprodução — 2026-10-11

Baseline: commit 658e3cd1b1442b66420210526531a0de0c7adb45, pacote Fase 3 de 2026-10-09.

## Evidências desta rodada

- Manifesto local: OK, 32 arquivos cobertos; manifesto exclui a si próprio. Pacote tem 33 arquivos.
- Python do ambiente: 3.12.14; README exige 3.13.
- PyMuPDF e cryptography disponíveis; comandos unshare, mount, chroot, setpriv e prlimit disponíveis.
- uid_map e gid_map: somente 0 → 0, comprimento 1.
- /opt/pyvenv inexistente.
- Tentativa da suíte completa não concluiu; erros observados em os.chown para UID aleatório de 200000 a 299999: OSError errno 22. Nenhum resultado 43/43 pode ser atribuído a esta rodada.
- Suíte direcionada sem worker isolado: 21/21, 0 falhas, 0 erros. Casos 09–21, 26, 27, 29, 30, 37, 38, 40, 41; unittest real, sem alteração dos testes ou baseline. São validações de entrada/roteamento, permissões da chave, falhas injetadas de launcher, persistência de tentativa incompleta e hashes dos módulos. Falhas injetadas não equivalem a isolamento real.

## Achados no código

1. runtime/phase3_broker.py atribui staging a UID aleatório alto com os.chown. Este host não mapeia tais UIDs; launcher não é portável para este ambiente.
2. runtime/namespace_entry.sh depende de /opt/pyvenv e executa /opt/pyvenv/bin/python; dependência ausente neste host.
3. A interface execute recebe envelope e caminhos diretamente. Não existe nesta baseline autenticação de identidade solicitante nem serviço separado que estabeleça a fronteira de acesso aos módulos. A própria documentação reconhece contorno fora do broker.
4. Ledger e chave HMAC residem no mesmo domínio administrativo; não há evidência de proteção contra administrador do host.

## Próximos passos

Recuperar a cópia experimental mais recente da Fase 4 antes de criar revisão substituta. Definir e validar ambiente Linux com identidades distintas para solicitante e serviço, política de acesso aos módulos e transporte autenticado. Reproduzir os 43 testes e adicionar testes de contorno externo usando ambas as identidades. Não adaptar namespaces por fallback nem considerar os 21 testes aprovação de segurança global.

Status: NO-GO para produção. Baseline e motores preservados. Nenhuma correção da Fase 4 implementada nesta rodada.
