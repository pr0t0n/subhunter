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
