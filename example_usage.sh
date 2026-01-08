#!/bin/bash
# Exemplo de uso do MedShield-X

echo "=== MedShield-X - Exemplo de Uso ==="
echo ""

# Exemplo 1: Scan completo
echo "1. Scan completo (Surface + Dark Web + DNS):"
echo "python -m src.main scan --brand 'medsenior' --domain 'medsenior.com' --json results.json --csv results.csv"
echo ""

# Exemplo 2: Apenas Surface Web
echo "2. Apenas Surface Web:"
echo "python -m src.main scan --brand 'medsenior' --no-darkweb --no-dns --json surface.json"
echo ""

# Exemplo 3: Apenas Dark Web
echo "3. Apenas Dark Web:"
echo "python -m src.main scan --brand 'medsenior' --no-surface --no-dns --json darkweb.json"
echo ""

# Exemplo 4: Testar Tor
echo "4. Testar conexão Tor:"
echo "python -m src.main test-tor"
echo ""

# Exemplo com Docker
echo "=== Usando Docker Compose ==="
echo ""
echo "1. Iniciar serviços:"
echo "docker-compose up -d tor-proxy"
echo ""
echo "2. Executar scan:"
echo "docker-compose exec app python -m src.main scan --brand 'medsenior' --domain 'medsenior.com'"
echo ""

