# MedShield-X - OSINT Brand Monitoring Tool

Ferramenta OSINT modular e pronta para produção para monitoramento de vazamentos de marca na Surface Web, Deep Web e Dark Web usando apenas recursos gratuitos. Inclui análise visual avançada com Computer Vision para detecção de phishing.

## 🎯 Características

- **Surface Web Scanner**: Busca usando DuckDuckGo em paste sites, repositórios públicos e arquivos sensíveis
- **Dark Web Scanner**: Busca em Ahmia.fi por menções em sites .onion e verifica feeds de ransomware
- **DNS/Typosquatting Scanner**: Detecta domínios suspeitos usando técnicas similares ao dnstwist
- **Visual Phishing Scanner** 🆕: Análise visual avançada usando Computer Vision:
  - Detecção de logo usando feature matching (ORB)
  - OCR com Tesseract para extração de texto
  - Análise de cores para identificar branding
  - Detecção de palavras-chave da marca
  - Score de phishing baseado em múltiplos fatores
- **Tor Integration**: Roteamento automático através do Tor para acessar sites .onion
- **Resilient Network**: Retry automático com exponential backoff usando tenacity
- **User-Agent Rotation**: Rotação automática de User-Agents para evitar bloqueios
- **Rich Output**: Tabelas formatadas no console + exportação JSON/CSV

## 📋 Requisitos

- Docker e Docker Compose
- Python 3.11+ (para execução local)
- Logo da marca em `./assets/logo.png` (para análise visual)

## 🚀 Instalação e Uso

### Usando Docker Compose (Recomendado)

1. **Clone ou navegue até o diretório do projeto:**
```bash
cd medshield-x
```

2. **Construa e inicie os serviços:**
```bash
docker-compose up --build
```

3. **Coloque o logo da marca em `./assets/logo.png`**

4. **Execute o scan (em outro terminal ou modifique o docker-compose.yml):**
```bash
docker-compose exec app python -m src.main scan \
  --brand "medsenior" \
  --domain "medsenior.com.br" \
  --json /app/reports/results.json \
  --csv /app/reports/results.csv \
  --visual
```

### Execução Local

1. **Instale as dependências:**
```bash
pip install -r requirements.txt
```

2. **Inicie o Tor proxy (usando Docker):**
```bash
docker run -d --name tor-proxy -p 9050:9050 dperson/torproxy
```

3. **Execute o scan:**
```bash
python -m src.main scan \
  --brand "medsenior" \
  --domain "medsenior.com" \
  --json results.json \
  --csv results.csv
```

## 📖 Comandos Disponíveis

### Scan Completo
```bash
python -m src.main scan \
  --brand "nome_da_marca" \
  --domain "dominio.com" \
  --surface \
  --darkweb \
  --dns \
  --json resultados.json \
  --csv resultados.csv
```

### Opções de Scan

- `--brand, -b`: Nome da marca para monitorar (obrigatório)
- `--domain, -d`: Domínio para verificar typosquatting (opcional)
- `--surface/--no-surface`: Habilitar/desabilitar scan de Surface Web (padrão: habilitado)
- `--darkweb/--no-darkweb`: Habilitar/desabilitar scan de Dark Web (padrão: habilitado)
- `--dns/--no-dns`: Habilitar/desabilitar scan DNS (padrão: habilitado)
- `--visual/--no-visual`: Habilitar/desabilitar análise visual de phishing (padrão: habilitado)
- `--logo`: Caminho para o logo da marca (padrão: `/app/assets/logo.png`)
- `--json, -j`: Caminho para arquivo JSON de saída
- `--csv, -c`: Caminho para arquivo CSV de saída
- `--tor-proxy`: URL do proxy Tor (padrão: `socks5h://tor-proxy:9050`)

### Testar Conexão Tor
```bash
python -m src.main test-tor
```

## 🏗️ Estrutura do Projeto

```
medshield-x/
├── assets/
│   └── logo.png             # Logo da marca (para análise visual)
├── src/
│   ├── main.py              # CLI entry point
│   ├── core/
│   │   └── network.py       # Cliente HTTP resiliente com roteamento Tor
│   └── scanners/
│       ├── surface.py       # Scanner Surface Web (DuckDuckGo)
│       ├── darkweb.py       # Scanner Dark Web (Ahmia + Ransomware)
│       ├── dns.py           # Scanner DNS/Typosquatting
│       └── visual.py        # Scanner Visual Phishing (CV + OCR)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 🔧 Arquitetura Técnica

### Network Client (`core/network.py`)

O `NetworkClient` detecta automaticamente URLs `.onion` e roteia através do proxy Tor SOCKS5. Para URLs normais, usa conexão HTTP/HTTPS padrão.

**Características:**
- Detecção automática de `.onion`
- Retry resiliente com tenacity (exponential backoff: 2s, 4s, 8s, 16s, 30s)
- Tratamento especial para HTTP 429 (Too Many Requests)
- Rotação automática de User-Agents
- Timeout configurável
- Suporte a async/await

### Scanners

#### Surface Web Scanner
- Usa `duckduckgo_search` para buscas sem API key
- Dorking em paste sites (Pastebin, Trello, GitHub, etc.)
- Busca por arquivos sensíveis (`.env`, `.config`, `.key`, etc.)
- Delays aleatórios para evitar rate limiting

#### Dark Web Scanner
- **Ahmia.fi**: Busca em índice de sites Tor
- **Ransomware Feeds**: Monitora feed do Ransomwatch no GitHub
- Validação de sites `.onion` (verifica se estão ativos)

#### DNS Scanner
- Gera variações de domínio usando técnicas de typosquatting:
  - Substituição de caracteres
  - Omissão de caracteres
  - Inserção de caracteres
  - Transposição
  - Variações de TLD
- Resolve DNS para verificar existência
- Identifica IPs e registros MX

#### Visual Phishing Scanner 🆕
- **Headless Browser**: Usa Playwright para visitar domínios suspeitos
- **Logo Detection**: Feature matching (ORB) para detectar logo mesmo se redimensionado
- **OCR**: Extração de texto com Tesseract (português + inglês)
- **Color Analysis**: Análise de cores dominantes para identificar branding MedSênior
- **Keyword Detection**: Busca por slogans da marca ("Bem Envelhecer", "Terceira Idade", etc.)
- **Phishing Score**: Sistema de pontuação baseado em múltiplos fatores:
  - Logo detectado: até 40 pontos
  - Palavras-chave: até 30 pontos
  - Cores da marca: até 30 pontos
  - Severidade: Critical (≥70), High (≥50), Medium (≥30), Low (<30)

## 📊 Formato de Saída

### JSON
```json
{
  "scan_timestamp": "2024-01-15T10:30:00",
  "total_findings": 5,
  "findings": [
    {
      "type": "surface_web",
      "title": "...",
      "url": "...",
      "severity": "high"
    }
  ]
}
```

### CSV
Exporta todos os campos dos findings em formato CSV planificado.

## ⚠️ Considerações de Segurança

1. **Tor Proxy**: O serviço Tor roda em container separado para isolamento
2. **Rate Limiting**: Delays aleatórios implementados para evitar bloqueios
3. **SSL/TLS**: Desabilitado para `.onion` (não suportado), habilitado para clearnet
4. **Logs**: Logging configurado para rastreamento de operações

## 🐛 Troubleshooting

### Tor não conecta
```bash
# Verifique se o container Tor está rodando
docker-compose ps

# Teste a conexão
docker-compose exec app python -m src.main test-tor
```

### Erro de DNS
- Certifique-se de que o domínio fornecido está correto
- O scanner DNS pode gerar muitos domínios - ajuste a lógica se necessário

### Rate Limiting
- Aumente os delays no `SurfaceWebScanner` (parâmetro `delay_range`)
- Reduza o número de resultados por query

## 📝 Licença

Este projeto é fornecido "como está" para fins de segurança e monitoramento legítimo.

## 🤝 Contribuições

Melhorias e correções são bem-vindas. Por favor, teste adequadamente antes de submeter.

---

**Desenvolvido como ferramenta OSINT para monitoramento de segurança de marca**

