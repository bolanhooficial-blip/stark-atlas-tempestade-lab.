# ECO — Fase 3: Controle Obrigatório de Execução e Isolamento Operacional

**Data:** 2026-10-09  
**Identificador:** ECO-MANDATORY-EXECUTION-ISOLATION-LAB-3.0  
**Estado:** IMPLEMENTADO E TESTADO EM AMBIENTE ISOLADO — **NÃO INSTALADO NA PRODUÇÃO**  
**Aplicação:** STARK–ATLAS–TEMPESTADE; TEMPESTADE/SPDA exclusivamente em estado bloqueado neste piloto.

## 1. Objetivo, limites e decisão

O objetivo é tornar obrigatório o encaminhamento por um supervisor para operações **dentro de um domínio de execução controlado**, usando isolamento de sistema operacional e registro durável. Não houve alteração dos motores originais, nem criação de um servidor de produção.

**Conclusão:** os testes demonstram que, ao invocar `MandatoryBroker` no ambiente Linux de testes, a classificação documental do STARK e a exportação preliminar do ATLAS podem passar por um trabalhador isolado por namespaces de usuário, montagem, PID, rede e chroot, com fontes explicitamente autorizadas. As operações `SPDA_CALCULATE` e `EXECUTIVE_RELEASE` foram bloqueadas. Testes de adulteração documental e do registro de evidências passaram. **Esse resultado não impede uma aplicação externa de importar/chamar diretamente o código antigo fora do domínio protegido.** Por isso a proteção **não está homologada** como barreira de produção.

## 2. Componentes entregues

- `runtime/phase3_broker.py`: entrada controlada, validação de envelope e hash dos bytes, roteamento allowlist, verificação dos módulos herdados, chave de execução vinculada a projeto/revisão/norma/ruleset/versões, ledger com transações SQLite e HMAC.
- `runtime/worker.py`: dispatcher estático, sem execução arbitrária nem abertura de cálculo SPDA ou entrega executiva.
- `runtime/namespace_entry.sh`: isolamento por namespaces, chroot, montagem apenas de bibliotecas de sistema de leitura, ausência de `/home`, `/mnt`, `/root`, `/proc`, `/sys` do host e isolamento de rede.
- `dependency_phase2/`: cópia integral dos módulos `.py` de referência usados pela Fase 2, acompanhada de manifesto de hashes, além do runtime correspondente. **Não são novas revisões dos motores.**
- `tests/test_phase3.py` e `proofs/`: testes e logs reais desta rodada.

## 3. Evidências de execução

| Suíte | Resultado | Escopo |
|---|---:|---|
| Fase 3 | **43/43** | Roteamento, sandbox, documentos, revisão, rede, integridade, falhas, retomada segura e concorrência |
| Regressão Fase 2 | **52/52** | Integração experimental STARK/TEIL/ATLAS |
| Regressão Fase 1 | **66/66** | Assinatura e fronteira documental/normativa sintética |
| Regressão original selecionada | **108/108** | EICF, TEIL, integração e orquestração de referência |

Fontes: `proofs/PHASE3_REPRODUCED.log`, `REGRESSION_PHASE2.log`, `REGRESSION_PHASE1.log`, `REGRESSION_ORIGINAL_108.log`.

**Observação:** o resultado 42 corresponde a **43 casos distintos**, sem contar testes herdados duas vezes. A validação posterior do pacote extraído em diretório privado detectou uma falha de portabilidade do launcher. O comando de isolamento passou a transmitir o script fixo pela opção `sh -c`, mantendo a execução sem fallback e vinculando o hash do script à chave de execução. Um teste adicional confirma a inicialização em diretório privado. Antes da correção de concorrência, a tentativa de uso da mesma conexão SQLite entre threads produziu erro de afinidade de conexão. A cópia da Fase 3 foi corrigida usando `check_same_thread=False` combinado a travamento por instância e lock de arquivo, e o teste específico de duas conexões passou. O código original da Fase 2 não foi modificado.

## 4. Propriedades verificadas no laboratório

1. Operações autorizadas: `CLASSIFY_STARK` e `EXPORT_ATLAS_DRAFT`, além de um `ISOLATION_PROBE` restrito a testes. Código de execução arbitrário é rejeitado.
2. Operações SPDA e liberação executiva negadas sem fallback.
3. Validação da identidade do projeto, revisão, origem e hash de cada documento antes de encaminhá-lo ao worker.
4. Cópias dos arquivos autorizados são colocadas em staging temporário, com UID isolado e sem expor o diretório original ao trabalhador.
5. Rejeição do mesmo identificador de execução em duplicidade; alterações de projeto, revisão, edição normativa e ruleset alteram a chave.
6. Ledger local persistente e encadeamento HMAC que detectam edições diretas nas tabelas, mudanças de estado e truncamento sem atualização da âncora.
7. Teste concorrente entre duas conexões confirma somente uma execução para a mesma chave; segunda tentativa é recusada.
8. Execução incompleta permanece `RUNNING` e **não** é automaticamente promovida; não há liberação silenciosa em caso de interrupção.
9. Documentos e outputs retornados são vinculados por hash. Saída preliminar PDF/PNG conserva estado `DRAFT_REVIEW_REQUIRED`.
10. O processo filho possui limites de recursos (memória virtual, CPU, tamanho máximo de arquivo, número de descritores). Disponibilidade sob ataque intenso **não** foi qualificada.

## 5. Limitações e riscos residuais — obrigatórios

- **R1 — Contorno fora do domínio:** aplicações que continuem com acesso de leitura/execução às bibliotecas originais poderão chamá-las diretamente. Ainda faltam implementação da política de implantação, permissões do sistema e revisão por terceiro que confirme bloqueio global na topologia real.
- **R2 — Linux específico:** testes executados em Linux com `unshare`, `chroot`, `setpriv`, `prlimit` e os mounts disponíveis. **Não** é uma instalação validada para Windows; não existe um instalador de produção.
- **R3 — Assinaturas reais:** esta fase não conectou identidade e assinatura profissional reais. Nenhuma aprovação humana operacional foi simulada como homologada.
- **R4 — SPDA não calculado:** nenhum resultado de SPDA conforme NBR 5419 foi produzido ou homologado; faltam as normas autorizadas e os três projetos reais.
- **R5 — Auditoria local:** SQLite e chave/âncora HMAC ficam no mesmo host; alguém com acesso administrativo a chave e registros pode adulterar ambos. Não há WORM, servidor remoto independente nem atestação externa.
- **R6 — Execução confiável:** o supervisor e as dependências são tratados como código confiável no laboratório. Não houve uma auditoria independente e completa de segurança da plataforma, nem qualificação de resistência a exploração de parsers ou indisponibilidade.
- **R7 — Recuperação:** uma transação interrompida entre confirmação no banco e gravação da âncora pode gerar bloqueio persistente. É falha segura, mas exige procedimento administrativo separado para recuperação auditável. Não foi implementado mecanismo de recuperação automática.
- **R8 — Dados não expostos:** todos os testes desta fase utilizaram documentos sintéticos. Nenhuma planta ou arquivo cliente deve ser usado neste laboratório antes de análise de privacidade/segurança da implantação.
- **R9 — Cobertura histórica:** a regressão de 108 testes abrange módulos selecionados, não representa validação de todas as centenas de arquivos históricos presentes em arquivos anteriores.

## 6. Critérios de aceitação para uma futura implantação

- Isolar o runtime confiável em conta/serviço sem permissões para executar diretamente os módulos antigos fora do supervisor, demonstrando o bloqueio por um teste de contorno externo.
- Autenticar solicitações e profissionais em infraestrutura controlada; rotacionar credenciais e preservar registros auditáveis.
- Estabelecer logs externos imutáveis, um plano de recuperação transacional e políticas de retenção.
- Demonstrar cada fonte efetivamente autorizada e as restrições de acesso após implantação.
- Validar deployment reproduzível em ambiente separado, com revisão externa dos requisitos de OS, limitações e dependências.
- Demonstrar referências normativas oficiais e os três ensaios cegos reais, com aprovação final do engenheiro habilitado.

## 7. Decisão operacional

**NO-GO para produção e para liberação executiva/SPDA automático.**  
**GO exclusivamente para desenvolvimento/testes isolados desta implementação de referência.**

Nenhum artefato original de STARK, ATLAS ou TEMPESTADE foi modificado. Esta é uma nova camada de laboratório e não altera as configurações constitucionais dos três motores.
