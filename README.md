# SubHunter

Ferramenta simples em Python para:

- Enumerar subdomínios a partir de uma wordlist
- Fazer port scan nas portas mais comuns
- Detectar tipo de aplicação via headers e conteúdo
- Exportar resultados para CSV

Instalação rápida:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

<<<<<<< HEAD
# SubHunter

SubHunter é uma ferramenta simples em Python para automação básica de descoberta
e enumeração de subdomínios, varredura de portas e fingerprinting de aplicações
e WAFs a partir de respostas HTTP. Gera resultados em CSV para posterior análise.

Principais funcionalidades
- Enumerar subdomínios a partir de uma wordlist (`subdomains.txt`)
- Fazer port-scan com portas carregadas de `ports.txt`
- Identificar aplicações via assinaturas em `apps_signatures.txt`
- Identificar WAFs via assinaturas em `waf_signatures.txt`
- Gerar CSV por domínio com colunas: host, ip, open_ports, http_url, http_status,
  server, x_powered_by, title, app_guess, waf

Requisitos
- Python 3.8+
- Dependências listadas em `requirements.txt` (ex.: `requests`)

Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Arquivos de configuração
- `subdomains.txt`: wordlist de prefixes (uma entrada por linha). Comentários com `#` são ignorados.
- `ports.txt`: lista de portas (um número por linha). Obrigatório.
- `apps_signatures.txt`: assinaturas de aplicações no formato `Name:pattern1,pattern2`.
- `waf_signatures.txt`: assinaturas de WAFs no mesmo formato.

Uso

Escanear um domínio:

```bash
python subhunter.py -d example.com -w subdomains.txt -o results.csv
```

Escanear vários domínios (arquivo com 1 domínio por linha):

```bash
python subhunter.py -l domains.txt -w subdomains.txt
```

Opções úteis
- `-t / --threads`: limitar threads para enumeração (padrão: 50)
- `-v / --verbose`: nível de verbosidade (0=quiet, 1=summary, 2=debug)

Considerações de segurança e uso
- Use esta ferramenta somente em alvos que você tem permissão para testar.
- Scans de portas e requests em larga escala podem gerar tráfego detectável.

Validação do `requirements.txt`
- O arquivo atual contém apenas dependências de runtime (`requests` e `certifi`).
- Para instalar:

```bash
pip install -r requirements.txt
```

Se desejar posso:
- travar versões no `requirements.txt` (ex.: `requests==2.32.5`) ou
- gerar um `requirements.lock` via `pip freeze` no ambiente virtual.

Contribuições
- Atualize `apps_signatures.txt` e `waf_signatures.txt` para melhorar a cobertura.
- Abra PRs para melhorar heurísticas ou adicionar suporte a novos checks.

Licença & Aviso
- Forneça/adicione aqui a licença desejada e use a ferramenta com responsabilidade.
=======
Uso:

```bash
python subhunter.py --domain example.com --wordlist subdomains.txt --output results.csv
```

Os resultados estarão em `results.csv`.

Observações:

- O scanner usa resolução DNS e tentativas de conexão TCP (não é exaustivo).
- Ajuste a `subdomains.txt` para melhorar a enumeração.
- Use com permissão do dono dos domínios alvo.
# subhunter
>>>>>>> e1b840bd24e572599d2b7437bf6eab3f660692fb
