# NetTracker Discord Bot

Um bot do Discord para gerenciamento e verificação de redes, que permite escanear redes para encontrar IPs disponíveis e obter informações sobre dispositivos conectados.

## Características

- 🔍 **Escaneamento de sub-redes**: Verifica todos os IPs em uma sub-rede para identificar endereços livres
- 🎯 **Verificação de IP específico**: Testa se um determinado IP está em uso ou disponível
- ⏭️ **Busca de IPs disponíveis**: Encontra os próximos IPs livres a partir de um endereço específico
- 📝 **Detalhes de IP**: Fornece informações detalhadas sobre um IP, incluindo hostname e endereço MAC
- ℹ️ **Informações de rede**: Exibe detalhes da configuração de rede atual

## Requisitos

- Python 3.8 ou superior
- discord.py 2.0 ou superior
- python-dotenv
- ipaddress

## Instalação

1. Clone o repositório
   ```bash
   git clone https://github.com/seu-usuario/nettracker-bot.git
   cd nettracker-bot
   ```

2. Instale as dependências
   ```bash
   pip install discord.py python-dotenv ipaddress
   ```

3. Configure as variáveis de ambiente
   ```bash
   cp .env.example .env
   ```
   Edite o arquivo `.env` e adicione seu token do Discord e outras configurações necessárias.

4. Execute o bot
   ```bash
   python nettracker.py
   ```

## Configuração

Edite o arquivo `.env` para configurar o bot:

```
DISCORD_TOKEN=seu_token_do_discord
```

Opcionalmente, você pode configurar a rede padrão e o gateway no código:

```python
DEFAULT_NETWORK = "192.168.1.0/24"  # Formato CIDR da sua rede
DEFAULT_GATEWAY = "192.168.1.1"     # Gateway padrão da rede
```

## Comandos

O bot oferece os seguintes comandos:

- `!nettools` - Abre o menu principal de ferramentas de rede
- `!scan_subnet <número>` - Escaneia IPs de uma sub-rede (exemplo: `!scan_subnet 0` para 192.168.1.0/24)
- `!check_ip <endereço>` - Verifica se um IP específico está disponível
- `!next_free <ip> <quantidade>` - Busca IPs livres a partir de um endereço
- `!ip_details <endereço>` - Exibe detalhes completos sobre um IP
- `!network_info` - Mostra informações sobre a rede configurada
- `!clean_dm <número>` - Limpa mensagens do bot no chat privado

## Como funciona

O bot usa múltiplos métodos para verificar IPs:
1. Verificação de tabela ARP (para equipamentos desligados, mas registrados)
2. Ping ICMP (para dispositivos ativos que respondem a ping)
3. Verificação de portas TCP (para dispositivos que bloqueiam ping, mas têm serviços ativos)

Isso garante maior precisão na identificação de dispositivos e IPs livres.

## Segurança e Privacidade

- Os resultados detalhados são enviados apenas por mensagem privada
- O bot limpa os comandos após processá-los para maior privacidade
- Apenas administradores com permissões apropriadas devem usar este bot

## Limitações

- O bot foi projetado para redes locais e pode não funcionar corretamente com sub-redes muito grandes
- Alguns firewalls podem bloquear pings ou verificações de portas, afetando a precisão
- A identificação de MAC e hostname depende de acesso à tabela ARP e serviços DNS locais

## Créditos

Desenvolvido por gones75, baseado em técnicas de gerenciamento de rede e monitoramento.

---

⚠️ **Nota de uso responsável**: Este bot só deve ser utilizado em redes em que você tem permissão para realizar escaneamentos e monitoramento.
