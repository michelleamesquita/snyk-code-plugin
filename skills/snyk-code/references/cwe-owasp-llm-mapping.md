# Mapeamento CWE → OWASP LLM Top 10 (2025)

## Tabela de mapeamento

| CWE | Nome | OWASP LLM | Descrição do risco em IA |
|---|---|---|---|
| CWE-20 | Improper Input Validation | LLM01 – Prompt Injection | Input não validado pode ser usado para injetar prompts maliciosos |
| CWE-74 | Injection | LLM01 – Prompt Injection | Variações de injection afetam modelos via prompt |
| CWE-116 | Improper Encoding/Escaping | LLM01 – Prompt Injection | Falta de encoding permite bypass de filtros de prompt |
| CWE-200 | Information Exposure | LLM02 – Sensitive Info Disclosure | Exposição de dados sensíveis em output do modelo |
| CWE-312 | Cleartext Storage of Sensitive Info | LLM06 – Sensitive Info Disclosure | Armazenamento sem criptografia de contexto/histórico |
| CWE-313 | Cleartext Storage in File | LLM06 – Sensitive Info Disclosure | System prompts ou configs armazenados em plain text |
| CWE-319 | Cleartext Transmission | LLM06 – Sensitive Info Disclosure | Chamadas à API do modelo sem TLS |
| CWE-327 | Use of Broken Crypto | LLM06 – Sensitive Info Disclosure | Algoritmos fracos protegendo dados do modelo |
| CWE-346 | Origin Validation Error | LLM07 – Insecure Plugin Design | Plugins/tools sem validação de origem das chamadas |
| CWE-352 | CSRF | LLM07 – Insecure Plugin Design | Ações não autorizadas via plugins conectados ao LLM |
| CWE-400 | Uncontrolled Resource Consumption | LLM04 – Model Denial of Service | Inputs enormes causando DoS no modelo |
| CWE-441 | Unintended Proxy | LLM07 – Insecure Plugin Design | LLM atuando como proxy não intencional para sistemas internos |
| CWE-502 | Deserialization of Untrusted Data | LLM08 – Excessive Agency | Deserialização perigosa em ações autônomas do agente |
| CWE-601 | Open Redirect | LLM07 – Insecure Plugin Design | Redirect aberto em plugins web do agente |
| CWE-611 | XML External Entity (XXE) | LLM07 – Insecure Plugin Design | XXE em parsers usados por tools/plugins do agente |
| CWE-732 | Incorrect Permission Assignment | LLM08 – Excessive Agency | Permissões excessivas para ações autônomas do agente |
| CWE-798 | Use of Hardcoded Credentials | LLM09 – Overreliance | Chaves de API hardcoded no código de integração |
| CWE-918 | SSRF | LLM07 – Insecure Plugin Design | SSRF em plugins permite acesso a serviços internos |
| CWE-1004 | Sensitive Cookie without HttpOnly | LLM06 – Sensitive Info Disclosure | Sessões do usuário acessíveis via JS/LLM |

## OWASP LLM Top 10 — 2025 (resumo)

| ID | Nome |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain Vulnerabilities |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

> Nota: a versão 2025 do OWASP LLM Top 10 reorganizou algumas categorias em relação à 2023/2024.
> Sempre confirmar com a versão mais recente em https://owasp.org/www-project-top-10-for-large-language-model-applications/
