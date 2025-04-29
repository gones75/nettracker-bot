import discord
from discord.ext import commands
from discord.ui import Select, View, Button
import ipaddress
import asyncio
import subprocess
import platform
import socket
import os
import re
import sys
import traceback
from dotenv import load_dotenv

# Modo Debug - ativar para ver erros detalhados
DEBUG_MODE = True

# Carregar token do arquivo .env ou definir diretamente
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')

# Se o método acima não funcionar, descomente a linha abaixo e coloque seu token
# TOKEN = "seu_token_aqui"

# Configuração específica para sua rede
DEFAULT_NETWORK = ""  # Sua rede com máscara 255.255.252.0
DEFAULT_GATEWAY = ""     # Seu gateway padrão

# Configurar intenções do bot
intents = discord.Intents.default()
intents.message_content = True

# Criar o bot
bot = commands.Bot(command_prefix='!', intents=intents)

# Função para verificar dependências
def check_dependencies():
    """Verifica se todas as dependências necessárias estão instaladas"""
    required_packages = [
        "discord.py", "python-dotenv", "asyncio", "ipaddress"
    ]
    
    missing = []
    for package in required_packages:
        try:
            if package == "discord.py":
                # discord.py já está importado como discord
                if not discord:
                    missing.append(package)
            elif package == "python-dotenv":
                # python-dotenv já foi importado como dotenv
                if not load_dotenv:
                    missing.append(package)
            elif package == "asyncio":
                # asyncio já foi importado
                if not asyncio:
                    missing.append(package)
            elif package == "ipaddress":
                # ipaddress já foi importado
                if not ipaddress:
                    missing.append(package)
        except:
            missing.append(package)
    
    if missing:
        print("ERRO: As seguintes dependências estão faltando:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nInstale-as usando: pip install " + " ".join(missing))
        return False
    
    return True

# Função para log de erros
def log_error(error_msg, error=None):
    """Registra erros detalhados no console"""
    if DEBUG_MODE:
        print("\n===== ERRO DETALHADO =====")
        print(error_msg)
        if error:
            print(f"Tipo de erro: {type(error).__name__}")
            print(f"Mensagem: {str(error)}")
            print("Traceback:")
            traceback.print_exc()
        print("==========================\n")
    else:
        print(f"ERRO: {error_msg}")

# Função para verificar se o sistema é Windows
def is_windows():
    return platform.system().lower() == 'windows'

# Função para verificar IPs com ping - com tratamento de erros
async def ping_ip(ip):
    """Verifica se um IP está respondendo usando ping"""
    try:
        param = '-n' if is_windows() else '-c'
        command = ['ping', param, '1', '-w', '1', str(ip)]
        
        if DEBUG_MODE:
            print(f"Executando comando ping: {' '.join(command)}")
        
        # Executa o comando ping com um timeout
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Espera pelo resultado com timeout de 1 segundo
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1.0)
            output = stdout.decode('utf-8', errors='ignore')
            
            if DEBUG_MODE and process.returncode != 0:
                print(f"Ping para {ip} falhou com código {process.returncode}")
                print(f"Saída: {output}")
            
            # Se o ping foi bem-sucedido (returncode=0), o IP está em uso
            if process.returncode == 0:
                return False  # IP está ocupado (em uso)
            else:
                return True   # IP está disponível (livre)
                
        except asyncio.TimeoutError:
            # Mata o processo se exceder o timeout
            process.kill()
            if DEBUG_MODE:
                print(f"Timeout ao executar ping para {ip}")
            return True  # Considera disponível se der timeout (ninguém respondeu)
    except Exception as e:
        log_error(f"Erro ao fazer ping para {ip}", e)
        return False  # Em caso de erro, consideramos como indisponível/ocupado por segurança

# Função para verificar se um IP está na tabela ARP - com tratamento de erros
async def check_arp(ip):
    """Verifica se um IP está na tabela ARP (mesmo se o PC estiver desligado)"""
    try:
        if is_windows():
            # Comando para Windows
            cmd = ['arp', '-a']
        else:
            # Comando para Linux
            cmd = ['arp', '-n']
        
        if DEBUG_MODE:
            print(f"Executando comando ARP: {' '.join(cmd)}")
            
        # Executar o comando
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        output = stdout.decode('utf-8', errors='ignore')
        
        if DEBUG_MODE:
            print(f"Verificando IP {ip} na tabela ARP")
            if stderr:
                err_output = stderr.decode('utf-8', errors='ignore')
                print(f"Erro na saída ARP: {err_output}")
        
        # Verificar se o IP aparece na saída
        ip_to_check = str(ip)
        
        if is_windows():
            # No Windows, o IP aparece com espaços
            return ip_to_check in output
        else:
            # No Linux, procurar padrão IP seguido de espaço
            return re.search(r'{}(\s|$)'.format(re.escape(ip_to_check)), output) is not None
        
    except Exception as e:
        log_error(f"Erro ao verificar ARP para {ip}", e)
        return False

# Função para verificar usando socket TCP - com tratamento de erros
async def check_tcp_port(ip, port=80, timeout=0.5):
    """Verifica se uma porta específica está aberta no IP"""
    try:
        if DEBUG_MODE:
            print(f"Verificando conexão TCP para {ip}:{port}")
            
        # Criar um socket non-blocking
        future = asyncio.open_connection(str(ip), port)
        
        # Tentar conectar com timeout
        try:
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            
            # Se conseguiu conectar, fecha a conexão e retorna ocupado
            if writer:
                if DEBUG_MODE:
                    print(f"Conexão TCP bem-sucedida para {ip}:{port}")
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
            
            return False  # IP está ocupado (porta aberta)
        except asyncio.TimeoutError:
            if DEBUG_MODE:
                print(f"Timeout ao conectar TCP para {ip}:{port}")
            return True   # IP está disponível (ninguém respondeu)
        except ConnectionRefusedError:
            # Recusou a conexão, mas o host existe
            if DEBUG_MODE:
                print(f"Conexão recusada para {ip}:{port} - host existe mas porta fechada")
            return False  # IP está ocupado (maquina existe mas porta fechada)
    except Exception as e:
        log_error(f"Erro ao verificar porta {port} em {ip}", e)
        return False  # Em caso de erro, consideramos como indisponível/ocupado por segurança

# Função para resolver hostname a partir do IP - com tratamento de erros
async def resolve_hostname(ip):
    """Tenta obter o nome do host a partir do IP"""
    try:
        if DEBUG_MODE:
            print(f"Tentando resolver hostname para {ip}")
            
        # Tentar resolução direta
        try:
            hostname, _, _ = socket.gethostbyaddr(str(ip))
            if DEBUG_MODE:
                print(f"Hostname resolvido: {hostname}")
            return hostname
        except Exception as e:
            if DEBUG_MODE:
                print(f"Falha na resolução direta: {str(e)}")
            
            # Se a resolução direta falhar, tentar via nslookup/nbtstat
            if is_windows():
                # Tentar nbtstat primeiro (mais detalhado para redes Windows)
                cmd = ['nbtstat', '-A', str(ip)]
                
                if DEBUG_MODE:
                    print(f"Executando: {' '.join(cmd)}")
                    
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                output = stdout.decode('utf-8', errors='ignore')
                
                if DEBUG_MODE and stderr:
                    err_output = stderr.decode('utf-8', errors='ignore')
                    print(f"Erro em nbtstat: {err_output}")
                
                # Tentar extrair o nome de host
                match = re.search(r'Nome.+?:(.*?)(?:\s|$)', output, re.IGNORECASE)
                if match and match.group(1).strip():
                    hostname = match.group(1).strip()
                    if DEBUG_MODE:
                        print(f"Hostname via nbtstat: {hostname}")
                    return hostname
                    
                # Se nbtstat falhar, tentar nslookup
                cmd = ['nslookup', str(ip)]
                
                if DEBUG_MODE:
                    print(f"Executando: {' '.join(cmd)}")
            else:
                # Para Linux/Mac
                cmd = ['host', str(ip)]
                
                if DEBUG_MODE:
                    print(f"Executando: {' '.join(cmd)}")
                
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            if DEBUG_MODE and stderr:
                err_output = stderr.decode('utf-8', errors='ignore')
                print(f"Erro em nslookup/host: {err_output}")
            
            # Procurar por um padrão de nome
            name_match = re.search(r'name(?:\s+pointer)?(?:\s+)?=(?:\s+)?([^\s,]+)', output, re.IGNORECASE)
            if name_match:
                hostname = name_match.group(1).rstrip('.')
                if DEBUG_MODE:
                    print(f"Hostname via nslookup/host: {hostname}")
                return hostname
            
        if DEBUG_MODE:
            print(f"Nenhum hostname encontrado para {ip}")
        return None
    except Exception as e:
        log_error(f"Erro ao resolver hostname para {ip}", e)
        return None

# Método melhorado de verificação (combina ping, arp e socket) - com tratamento de erros
async def is_ip_available(ip):
    """Método melhorado para verificar se um IP está disponível"""
    try:
        if DEBUG_MODE:
            print(f"\nVerificando disponibilidade do IP {ip}")
            
        # Primeiro verifica ARP (se estiver na tabela ARP, está em uso mesmo que desligado)
        arp_result = await check_arp(ip)
        if arp_result:
            if DEBUG_MODE:
                print(f"IP {ip} encontrado na tabela ARP -> EM USO")
            return False  # IP está na tabela ARP, então está em uso (mesmo desligado)
        
        # Depois tenta ping
        ping_result = await ping_ip(ip)
        
        # Se o ping indicar que está livre, tenta conexão TCP para confirmação
        if ping_result:
            if DEBUG_MODE:
                print(f"Ping para {ip} falhou -> verificando portas TCP")
                
            # Tenta verificar portas comuns
            tcp_80 = await check_tcp_port(ip, 80)   # HTTP
            tcp_22 = await check_tcp_port(ip, 22)   # SSH
            tcp_443 = await check_tcp_port(ip, 443) # HTTPS
            
            # Se todas as portas deram como livre, considera o IP disponível
            is_available = tcp_80 and tcp_22 and tcp_443
            
            if DEBUG_MODE:
                if is_available:
                    print(f"Todas as portas TCP para {ip} falharam -> LIVRE")
                else:
                    print(f"Pelo menos uma porta TCP para {ip} respondeu -> EM USO")
                    
            return is_available
        else:
            if DEBUG_MODE:
                print(f"Ping para {ip} bem-sucedido -> EM USO")
        
        # Se ping já indicou que está ocupado, não precisa verificar portas
        return False
    except Exception as e:
        log_error(f"Erro ao verificar disponibilidade do IP {ip}", e)
        return False  # Em caso de erro, consideramos como indisponível/ocupado por segurança

# Função para obter detalhes completos sobre um IP - com tratamento de erros
async def get_ip_details(ip):
    """Obtém detalhes completos sobre um IP (status, MAC, hostname)"""
    try:
        if DEBUG_MODE:
            print(f"\nObtendo detalhes para o IP {ip}")
            
        details = {
            "ip": str(ip),
            "status": "desconhecido",
            "mac_address": None,
            "hostname": None,
            "responde_ping": False
        }
        
        # Verificar se responde a ping
        ping_result = not await ping_ip(ip)  # Inverter lógica: False=livre, True=ocupado
        details["responde_ping"] = ping_result
        
        if DEBUG_MODE:
            print(f"Responde a ping: {ping_result}")
        
        # Verificar se está na tabela ARP
        arp_result = await check_arp(ip)
        
        if DEBUG_MODE:
            print(f"Está na tabela ARP: {arp_result}")
        
        # Obter o hostname (se disponível)
        hostname = await resolve_hostname(ip)
        if hostname:
            details["hostname"] = hostname
            if DEBUG_MODE:
                print(f"Hostname: {hostname}")
        
        # Determinar o status final
        if ping_result:
            details["status"] = "ativo (responde ping)"
        elif arp_result:
            details["status"] = "registrado (na tabela ARP, provavelmente desligado)"
        else:
            # Verificar portas TCP
            tcp_80 = not await check_tcp_port(ip, 80)
            tcp_22 = not await check_tcp_port(ip, 22)
            tcp_443 = not await check_tcp_port(ip, 443)
            
            if DEBUG_MODE:
                print(f"Responde porta 80: {tcp_80}")
                print(f"Responde porta 22: {tcp_22}")
                print(f"Responde porta 443: {tcp_443}")
            
            if tcp_80 or tcp_22 or tcp_443:
                details["status"] = "ativo (responde em portas TCP)"
            else:
                details["status"] = "livre (disponível)"
        
        # Obter MAC se estiver na tabela ARP
        if arp_result:
            try:
                if is_windows():
                    cmd = ['arp', '-a', str(ip)]
                else:
                    cmd = ['arp', '-n', str(ip)]
                
                if DEBUG_MODE:
                    print(f"Executando comando para obter MAC: {' '.join(cmd)}")
                    
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                output = stdout.decode('utf-8', errors='ignore')
                
                if DEBUG_MODE and stderr:
                    err_output = stderr.decode('utf-8', errors='ignore')
                    print(f"Erro ao obter MAC: {err_output}")
                
                # Extrair o endereço MAC
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                if mac_match:
                    details["mac_address"] = mac_match.group(1)
                    if DEBUG_MODE:
                        print(f"MAC obtido: {details['mac_address']}")
            except Exception as e:
                log_error(f"Erro ao obter MAC para {ip}", e)
        
        return details
    except Exception as e:
        log_error(f"Erro ao obter detalhes do IP {ip}", e)
        return {
            "ip": str(ip),
            "status": "erro ao verificar",
            "mac_address": None,
            "hostname": None,
            "responde_ping": False
        }

# Enviar resultados por mensagem direta - com tratamento de erros
async def send_dm_results(user, title, results, cmd_equivalent=""):
    """Envia resultados por DM para o usuário"""
    try:
        if DEBUG_MODE:
            print(f"Enviando DM para {user.name} com título: {title}")
            
        # Dividir em blocos se necessário para não exceder limite de mensagens
        if len(results) > 1900:  # Limite de caracteres do Discord
            chunks = []
            current_chunk = ""
            for line in results.split('\n'):
                if len(current_chunk) + len(line) + 1 > 1900:
                    chunks.append(current_chunk)
                    current_chunk = line
                else:
                    if current_chunk:
                        current_chunk += '\n'
                    current_chunk += line
            if current_chunk:
                chunks.append(current_chunk)
            
            # Enviar mensagem inicial
            await user.send(f"📋 **{title}**\n\n{cmd_equivalent}")
            
            # Enviar cada bloco
            for i, chunk in enumerate(chunks):
                await user.send(f"```\n{chunk}\n```")
            
            if DEBUG_MODE:
                print(f"Enviados {len(chunks)} blocos de resultados para {user.name}")
                
            return True
        else:
            # Enviar tudo em uma única mensagem
            message = f"📋 **{title}**\n\n{cmd_equivalent}\n```\n{results}\n```"
            await user.send(message)
            
            if DEBUG_MODE:
                print(f"Enviada única mensagem de resultados para {user.name}")
                
            return True
    except Exception as e:
        log_error(f"Erro ao enviar DM para {user}", e)
        return False
# Classe principal para o menu de funcionalidades simplificado
class SimpleMenuView(View):
    def __init__(self):
        super().__init__(timeout=None) 
    
    @discord.ui.button(label="Verificar IPs livres em sub-rede", style=discord.ButtonStyle.primary)
    async def scan_subnet_button(self, interaction, button):
        await interaction.response.send_message(
            "Enviando instruções para seu privado...", 
            ephemeral=True
        )
        
        await interaction.user.send(
            "🔍 **Verificar IPs livres em sub-rede**\n\n"
            "Para verificar uma sub-rede, use o comando:\n"
            "`!scan_subnet 0` - Para verificar a sub-rede 0\n"
            "`!scan_subnet 1` - Para verificar a sub-rede 1\n"
            "`!scan_subnet 2` - Para verificar a sub-rede 2\n"
            "`!scan_subnet 3` - Para verificar a sub-rede 3\n"
        )
    
    @discord.ui.button(label="Verificar um IP específico", style=discord.ButtonStyle.primary)
    async def check_ip_button(self, interaction, button):
        await interaction.response.send_message(
            "Enviando instruções para seu privado...", 
            ephemeral=True
        )
        
        await interaction.user.send(
            "🎯 **Verificar um IP específico**\n\n"
            "Para verificar se um IP está disponível, use o comando:\n"
            "`!check_ip`\n\n"
            "(Substitua o endereço pelo IP que deseja verificar)"
        )
    
    @discord.ui.button(label="Encontrar próximos IPs livres", style=discord.ButtonStyle.primary)
    async def next_free_button(self, interaction, button):
        await interaction.response.send_message(
            "Enviando instruções para seu privado...", 
            ephemeral=True
        )
        
        await interaction.user.send(
            "⏭️ **Encontrar Próximos IPs Livres**\n\n"
            "Para encontrar IPs livres a partir de um endereço, use o comando:\n"
            "`!next_free`\n\n"
            "(O primeiro parâmetro é o IP inicial e o segundo é a quantidade de IPs a encontrar)"
        )
    
    @discord.ui.button(label="Detalhar IP e Hostname", style=discord.ButtonStyle.primary)
    async def ip_details_button(self, interaction, button):
        await interaction.response.send_message(
            "Enviando instruções para seu privado...", 
            ephemeral=True
        )
        
        await interaction.user.send(
            "📝 **Detalhar IP e Hostname**\n\n"
            "Para obter detalhes completos sobre um IP, use o comando:\n"
            "`!ip_details`\n\n"
            "(Substitua o endereço pelo IP que deseja analisar)"
        )
    
    @discord.ui.button(label="Informações da rede", style=discord.ButtonStyle.secondary)
    async def network_info_button(self, interaction, button):
        await interaction.response.send_message(
            "Enviando instruções para seu privado...", 
            ephemeral=True
        )
        
        await interaction.user.send(
            "ℹ️ **Informações da Rede**\n\n"
            "Para ver informações completas sobre a rede, use o comando:\n"
            "`!network_info`"
        )

# Classe original do menu
class NetworkToolsView(View):
    def __init__(self):
        super().__init__(timeout=None)  # Menu sem timeout
        
        # Criar o menu de seleção
        select = Select(
            placeholder="Selecione uma ferramenta de rede...",
            options=[
                discord.SelectOption(
                    label="Verificar IPs livres em sub-rede",
                    description="Escaneia uma sub-rede /24 específica",
                    emoji="🔍",
                    value="scan_subnet"
                ),
                discord.SelectOption(
                    label="Verificar um IP específico",
                    description="Verifica se um endereço IP está livre",
                    emoji="🎯",
                    value="check_ip"
                ),
                discord.SelectOption(
                    label="Encontrar próximos IPs livres",
                    description="Busca IPs disponíveis a partir de um endereço",
                    emoji="⏭️",
                    value="next_free"
                ),
                discord.SelectOption(
                    label="Detalhar IP e Hostname",
                    description="Obtém informações detalhadas sobre um IP",
                    emoji="📝",
                    value="ip_details"
                ),
                discord.SelectOption(
                    label="Informações da rede",
                    description="Mostra detalhes sobre a rede configurada",
                    emoji="ℹ️",
                    value="network_info"
                ),
            ]
        )
        
        # Configurar o callback para quando uma opção for selecionada
        select.callback = self.select_callback
        self.add_item(select)
    
    async def select_callback(self, interaction):
        """Chamado quando o usuário seleciona uma opção no menu"""
        try:
            if DEBUG_MODE:
                print(f"\nUsuário {interaction.user.name} selecionou uma opção")
                
            selected_value = interaction.data["values"][0]
            
            if DEBUG_MODE:
                print(f"Opção selecionada: {selected_value}")
            
            if selected_value == "scan_subnet":
                await interaction.response.send_message(
                    f"🔍 **Verificação de IPs Livres em Sub-rede**\n\n"
                    f"Ok, {interaction.user.mention}, qual sub-rede da rede  você deseja verificar?\n\n"
                    f"Opções: 0, 1, 2 ou 3\n"
                    f"(Exemplo: Digite '2' para verificar a sub-rede 2n\n",
                    view=SubnetInputView(),
                    ephemeral=True  # Mensagem visível apenas para o usuário que interagiu
                )
            
            elif selected_value == "check_ip":
                if DEBUG_MODE:
                    print("Enviando view de verificação de IP")
                    
                try:
                    # Versão simplificada sem modal
                    await interaction.response.send_message(
                        f"🎯 **Verificação de IP Específico**\n\n"
                        f"Ok, {interaction.user.mention}, digite abaixo o IP que deseja verificar:",
                        ephemeral=True
                    )
                except Exception as e:
                    log_error(f"Erro ao enviar mensagem de verificação de IP", e)
                    # Tentar abordagem alternativa se falhar
                    await interaction.response.send_message(
                        "❌ Ocorreu um erro ao processar seu pedido. Por favor, tente novamente ou use o comando direto:\n"
                        "`!check_ip`",
                        ephemeral=True
                    )
            
            elif selected_value == "next_free":
                if DEBUG_MODE:
                    print("Enviando view de próximos IPs livres")
                    
                try:
                    # Versão simplificada sem modal
                    await interaction.response.send_message(
                        f"⏭️ **Encontrar Próximos IPs Livres**\n\n"
                        f"Ok, {interaction.user.mention}, digite abaixo o IP inicial e quantidade:",
                        ephemeral=True
                    )
                except Exception as e:
                    log_error(f"Erro ao enviar mensagem de próximos IPs livres", e)
                    # Tentar abordagem alternativa se falhar
                    await interaction.response.send_message(
                        "❌ Ocorreu um erro ao processar seu pedido. Por favor, tente novamente ou use o comando direto:\n"
                        "`!next_free`",
                        ephemeral=True
                    )
            
            elif selected_value == "ip_details":
                if DEBUG_MODE:
                    print("Enviando view de detalhes de IP")
                    
                try:
                    # Versão simplificada sem modal
                    await interaction.response.send_message(
                        f"📝 **Detalhar IP e Hostname**\n\n"
                        f"Ok, {interaction.user.mention}, digite abaixo o IP que deseja analisar em detalhes:",
                        ephemeral=True
                    )
                except Exception as e:
                    log_error(f"Erro ao enviar mensagem de detalhes de IP", e)
                    # Tentar abordagem alternativa se falhar
                    await interaction.response.send_message(
                        "❌ Ocorreu um erro ao processar seu pedido. Por favor, tente novamente ou use o comando direto:\n"
                        "`!ip_details ",
                        ephemeral=True
                    )
            
            elif selected_value == "network_info":
                await show_network_info(interaction)
        
        except Exception as e:
            log_error(f"Erro no callback de seleção", e)
            await interaction.response.send_message(
                "❌ Ocorreu um erro ao processar sua seleção. Por favor, tente novamente. Se o erro persistir, verifique o console para detalhes.",
                ephemeral=True
            )


# Views para cada funcionalidade do bot
class SubnetInputView(View):
    def __init__(self):
        super().__init__(timeout=60)  # Timeout de 60 segundos
    
    @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.red)
    async def cancel_button(self, interaction, button):
        try:
            if DEBUG_MODE:
                print(f"Usuário {interaction.user.name} cancelou a operação")
                
            await interaction.response.send_message("❌ Operação cancelada.", ephemeral=True)
            self.stop()
        except Exception as e:
            log_error(f"Erro ao cancelar operação", e)
            await interaction.response.send_message("❌ Erro ao cancelar.", ephemeral=True)
    
    @discord.ui.button(label="Sub-rede 0", style=discord.ButtonStyle.primary)
    async def subnet_0_button(self, interaction, button):
        try:
            if DEBUG_MODE:
                print(f"Usuário {interaction.user.name} selecionou sub-rede 0")
                
            await interaction.response.defer(ephemeral=True)
            await scan_subnet(interaction, "0")
            self.stop()
        except Exception as e:
            log_error(f"Erro ao processar sub-rede 0", e)
            await interaction.followup.send("❌ Erro ao processar a sub-rede 0. Verifique o console para detalhes.", ephemeral=True)
    
    @discord.ui.button(label="Sub-rede 1", style=discord.ButtonStyle.primary)
    async def subnet_1_button(self, interaction, button):
        try:
            if DEBUG_MODE:
                print(f"Usuário {interaction.user.name} selecionou sub-rede 1")
                
            await interaction.response.defer(ephemeral=True)
            await scan_subnet(interaction, "1")
            self.stop()
        except Exception as e:
            log_error(f"Erro ao processar sub-rede 1", e)
            await interaction.followup.send("❌ Erro ao processar a sub-rede 1. Verifique o console para detalhes.", ephemeral=True)
    
    @discord.ui.button(label="Sub-rede 2", style=discord.ButtonStyle.primary)
    async def subnet_2_button(self, interaction, button):
        try:
            if DEBUG_MODE:
                print(f"Usuário {interaction.user.name} selecionou sub-rede 2")
                
            await interaction.response.defer(ephemeral=True)
            await scan_subnet(interaction, "2")
            self.stop()
        except Exception as e:
            log_error(f"Erro ao processar sub-rede 2", e)
            await interaction.followup.send("❌ Erro ao processar a sub-rede 2. Verifique o console para detalhes.", ephemeral=True)
    
    @discord.ui.button(label="Sub-rede 3", style=discord.ButtonStyle.primary)
    async def subnet_3_button(self, interaction, button):
        try:
            if DEBUG_MODE:
                print(f"Usuário {interaction.user.name} selecionou sub-rede 3")
                
            await interaction.response.defer(ephemeral=True)
            await scan_subnet(interaction, "3")
            self.stop()
        except Exception as e:
            log_error(f"Erro ao processar sub-rede 3", e)
            await interaction.followup.send("❌ Erro ao processar a sub-rede 3. Verifique o console para detalhes.", ephemeral=True)


# Funções de processamento para cada funcionalidade
async def scan_subnet(interaction, subnet_number):
    try:
        if DEBUG_MODE:
            print(f"\nIniciando escaneamento da sub-rede {subnet_number}")
            
        # Converter para inteiro
        subnet = int(subnet_number)
        
        # Verificar se está no intervalo válido para uma rede /22 (0-3)
        if subnet < 0 or subnet > 3:
            await interaction.followup.send("❌ Para uma rede /22 (255.255.252.0), o número da sub-rede deve estar entre 0 e 3.", ephemeral=True)
            return
        
        # Construir o CIDR da sub-rede
        network_cidr = f".{subnet}.0/24"
        
        # Mensagem inicial
        await interaction.followup.send(f"🔍 Escaneando a sub-rede {network_cidr}. Isso pode levar algum tempo...", ephemeral=True)
        
        # Verificar a rede
        network = ipaddress.ip_network(network_cidr, strict=False)
        
        # Lista para armazenar IPs livres
        free_ips = []
        
        # Lista para armazenar erros de verificação
        errors = []
        
        # Para redes menores, vamos limitar o número de IPs verificados simultaneamente
        batch_size = 25  # Verificar 25 IPs por vez (reduzido para não sobrecarregar)
        
        all_ips = list(network.hosts())
        total_batches = (len(all_ips) + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min((batch_num + 1) * batch_size, len(all_ips))
            
            # IPs a serem verificados neste lote
            batch_ips = all_ips[start_idx:end_idx]
            
            # Tarefas para verificar os IPs do lote
            tasks = [is_ip_available(ip) for ip in batch_ips]
            
            # Executar as tarefas do lote simultaneamente
            try:
                results = await asyncio.gather(*tasks)
                
                # Adicionar IPs livres à lista
                batch_free_ips = [str(ip) for ip, is_free in zip(batch_ips, results) if is_free]
                free_ips.extend(batch_free_ips)
                
                # Atualizar a mensagem de progresso
                progress = min(100, int((end_idx) / len(all_ips) * 100))
                await interaction.followup.send(
                    f"🔍 Escaneando a sub-rede {network_cidr}: {progress}% concluído... ({len(free_ips)} IPs livres encontrados até agora)",
                    ephemeral=True
                )
            except Exception as e:
                error_msg = f"Erro ao verificar lote {batch_num+1}/{total_batches}: {str(e)}"
                errors.append(error_msg)
                log_error(error_msg, e)
                await interaction.followup.send(
                    f"⚠️ Erro ao verificar alguns IPs no lote {batch_num+1}/{total_batches}. Continuando...",
                    ephemeral=True
                )
            
            # Pequena pausa entre os lotes para não sobrecarregar
            await asyncio.sleep(1.0)
        
        # Verificar se encontramos IPs livres
        if free_ips:
            # Mensagem final no canal (apenas para o usuário)
            await interaction.followup.send(
                f"✅ Escaneamento concluído! Encontrados {len(free_ips)} IPs livres na sub-rede {network_cidr}. Os resultados foram enviados para sua mensagem privada.",
                ephemeral=True
            )
            
            # Adicionar mensagem sobre possíveis falsos positivos
            free_ips_text = '\n'.join(free_ips)
            if errors:
                free_ips_text += "\n\n⚠️ ATENÇÃO: Ocorreram alguns erros durante a verificação que podem afetar a precisão dos resultados."
                free_ips_text += "\nSempre confirme manualmente antes de usar um IP."
            
            # Enviar resultados por DM
            dm_success = await send_dm_results(
                interaction.user,
                f"IPs livres na sub-rede {network_cidr}",
                free_ips_text,
            )
            
            if not dm_success:
                await interaction.followup.send(
                    "⚠️ Não foi possível enviar os resultados por mensagem privada. Verifique se suas DMs estão abertas.",
                    ephemeral=True
                )
        else:
            await interaction.followup.send(
                f"❌ Nenhum IP livre encontrado na sub-rede {network_cidr}",
                ephemeral=True
            )
    
    except ValueError as e:
        log_error(f"Erro de valor ao escanear sub-rede", e)
        await interaction.followup.send("❌ O número da sub-rede deve ser um número inteiro válido.", ephemeral=True)
    except Exception as e:
        log_error(f"Erro ao escanear a sub-rede {subnet_number}", e)
        await interaction.followup.send(f"❌ Erro ao escanear a sub-rede: {str(e)}", ephemeral=True)


async def check_ip(user, ip_address, original_message=None):
    try:
        if DEBUG_MODE:
            print(f"\nVerificando IP específico: {ip_address} para {user.name}")
            
        # Verificar se o formato do IP é válido
        ip = ipaddress.ip_address(ip_address)
        
        # Criar mensagem de processamento
        processing_msg = None
        if original_message:
            processing_msg = await original_message.channel.send(f"🔍 Verificando disponibilidade do IP {ip_address}...")
        
        # Verificar IP usando método aprimorado
        is_free = await is_ip_available(ip)
        
        if is_free:
            result = f"✅ O IP {ip_address} parece estar DISPONÍVEL (livre)!"
        else:
            result = f"❌ O IP {ip_address} parece estar EM USO (ocupado)."
            
            # Se estiver em uso, tentar resolver o hostname
            hostname = await resolve_hostname(ip)
            if hostname:
                result += f"\n\nNome do host: {hostname}"
        
        # Enviar resultado por DM
        dm_sent = await send_dm_results(
            user,
            f"Verificação do IP {ip_address}",
            result,
        )
        
        # Se a mensagem DM foi enviada e há mensagem de processamento, atualizá-la
        if dm_sent and processing_msg:
            await processing_msg.edit(content=f"{user.mention} Verificação do IP {ip_address} concluída. Resultados enviados por mensagem privada.")
            await asyncio.sleep(5)
            await processing_msg.delete()
        elif processing_msg:
            await processing_msg.edit(content=f"❌ Não foi possível enviar mensagem privada para {user.mention}. Verifique se suas DMs estão abertas.")
            await asyncio.sleep(5)
            await processing_msg.delete()
    
    except ValueError as e:
        log_error(f"Formato de IP inválido: {ip_address}", e)
        if original_message:
            error_msg = await original_message.channel.send("❌ Formato de IP inválido. Use um endereço IPv4 válido")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send("❌ Formato de IP inválido. Use um endereço IPv4 válido")
    except Exception as e:
        log_error(f"Erro ao verificar o IP: {ip_address}", e)
        if original_message:
            error_msg = await original_message.channel.send(f"❌ Erro ao verificar o IP: {str(e)}")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send(f"❌ Erro ao verificar o IP: {str(e)}")


async def ip_details(user, ip_address, original_message=None):
    try:
        if DEBUG_MODE:
            print(f"\nObtendo detalhes do IP: {ip_address} para {user.name}")
            
        # Verificar se o formato do IP é válido
        ip = ipaddress.ip_address(ip_address)
        
        # Criar mensagem de processamento
        processing_msg = None
        if original_message:
            processing_msg = await original_message.channel.send(f"🔍 Obtendo detalhes para o IP {ip_address}...")
        
        # Obter detalhes completos
        details = await get_ip_details(ip)
        
        # Criar string de resultado formatada
        result = f"📝 **Detalhes do IP: {details['ip']}**\n\n"
        result += f"Status: {details['status']}\n"
        
        if details['hostname']:
            result += f"Hostname: {details['hostname']}\n"
        else:
            result += "Hostname: Não resolvido\n"
            
        if details['mac_address']:
            result += f"Endereço MAC: {details['mac_address']}\n"
        else:
            result += "Endereço MAC: Não encontrado\n"
            
        result += f"Responde a ping: {'Sim' if details['responde_ping'] else 'Não'}\n"
        
        # Enviar resultado por DM
        dm_sent = await send_dm_results(
            user,
            f"Detalhes do IP {ip_address}",
            result,
        )
        
        # Se a mensagem DM foi enviada e há mensagem de processamento, atualizá-la
        if dm_sent and processing_msg:
            await processing_msg.edit(content=f"{user.mention} Detalhes do IP {ip_address} concluídos. Resultados enviados por mensagem privada.")
            await asyncio.sleep(5)
            await processing_msg.delete()
        elif processing_msg:
            await processing_msg.edit(content=f"❌ Não foi possível enviar mensagem privada para {user.mention}. Verifique se suas DMs estão abertas.")
            await asyncio.sleep(5)
            await processing_msg.delete()
            
    
    except ValueError as e:
        log_error(f"Formato de IP inválido: {ip_address}", e)
        if original_message:
            error_msg = await original_message.channel.send("❌ Formato de IP inválido. Use um endereço IPv4 válido")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send("❌ Formato de IP inválido. Use um endereço IPv4 válido")
    except Exception as e:
        log_error(f"Erro ao obter detalhes do IP: {ip_address}", e)
        if original_message:
            error_msg = await original_message.channel.send(f"❌ Erro ao obter detalhes do IP: {str(e)}")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send(f"❌ Erro ao obter detalhes do IP: {str(e)}")


async def find_next_free(user, start_ip, count=5, original_message=None):
    try:
        if DEBUG_MODE:
            print(f"\nBuscando IPs livres a partir de: {start_ip}, quantidade: {count} para {user.name}")
            
        # Verificar se o formato do IP é válido
        ip = ipaddress.ip_address(start_ip)
        
        # Limitar o número de IPs a procurar
        if count > 20:
            count = 20  # Máximo de 20 IPs
        
        # Criar mensagem de processamento
        processing_msg = None
        if original_message:
            processing_msg = await original_message.channel.send(f"🔍 Procurando {count} IPs livres a partir de {start_ip}...")
        
        # Lista para armazenar IPs livres
        free_ips = []
        checked = 0
        current_ip = ip
        
        # Procurar até encontrar o número solicitado de IPs livres ou verificar 100 IPs
        while len(free_ips) < count and checked < 100:
            # Verificar IP atual usando método aprimorado
            is_free = await is_ip_available(current_ip)
            
            if is_free:
                free_ips.append(str(current_ip))
                if DEBUG_MODE:
                    print(f"IP livre encontrado: {current_ip} ({len(free_ips)}/{count})")
            
            # Avançar para o próximo IP
            current_ip = ipaddress.ip_address(int(current_ip) + 1)
            checked += 1
        
        # Criar string de comando CMD equivalente
        subnet_part = '.'.join(str(ip).split('.')[:3])
        last_octet = str(ip).split('.')[-1]
        
        # Verificar se encontramos IPs livres
        if free_ips:
            # Enviar resultado por DM
            dm_sent = await send_dm_results(
                user,
                f"IPs livres a partir de {start_ip}",
                '\n'.join(free_ips),
            )
            
            # Se a mensagem DM foi enviada e há mensagem de processamento, atualizá-la
            if dm_sent and processing_msg:
                await processing_msg.edit(content=f"{user.mention} Busca por IPs livres a partir de {start_ip} concluída. Resultados enviados por mensagem privada.")
                await asyncio.sleep(5)
                await processing_msg.delete()
            elif processing_msg:
                await processing_msg.edit(content=f"❌ Não foi possível enviar mensagem privada para {user.mention}. Verifique se suas DMs estão abertas.")
                await asyncio.sleep(5)
                await processing_msg.delete()
        else:
            if processing_msg:
                await processing_msg.edit(content=f"❌ Nenhum IP livre encontrado a partir de {start_ip} (verificados {checked} IPs)")
                await asyncio.sleep(5)
                await processing_msg.delete()
            else:
                await user.send(f"❌ Nenhum IP livre encontrado a partir de {start_ip} (verificados {checked} IPs)")
                
    
    except ValueError as e:
        log_error(f"Formato de IP inválido: {start_ip}", e)
        if original_message:
            error_msg = await original_message.channel.send("❌ Formato de IP inválido. Use um endereço IPv4 válido0")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send("❌ Formato de IP inválido. Use um endereço IPv4 válido")
    except Exception as e:
        log_error(f"Erro ao procurar IPs livres a partir de: {start_ip}", e)
        if original_message:
            error_msg = await original_message.channel.send(f"❌ Erro ao procurar IPs livres: {str(e)}")
            await asyncio.sleep(5)
            await error_msg.delete()
        else:
            await user.send(f"❌ Erro ao procurar IPs livres: {str(e)}")


async def show_network_info(interaction):
    try:
        if DEBUG_MODE:
            print(f"\nMostrando informações da rede para {interaction.user.name}")
            
        # Obter informações da rede padrão
        network = ipaddress.ip_network(DEFAULT_NETWORK, strict=False)
        
        # Calcular informações da rede
        info = f"""
📊 **Informações da Rede**

🌐 **Rede:** {DEFAULT_NETWORK}
🔑 **Gateway:** {DEFAULT_GATEWAY}
🎭 **Máscara:** {network.netmask} (/{network.prefixlen})
📍 **Endereço de Rede:** {network.network_address}
📡 **Endereço de Broadcast:** {network.broadcast_address}
🔢 **Total de Endereços:** {network.num_addresses}
📈 **Faixa de IPs Utilizáveis:** {network.network_address + 1} até {network.broadcast_address - 1}
🧩 **Sub-redes em /24:** {', '.join([f'{i}.0/24' for i in range(4)])}

**Comandos CMD equivalentes:**

ipconfig /all                        (ver configuração de rede)
nslookup {DEFAULT_GATEWAY}           (resolver DNS do gateway)
tracert {DEFAULT_GATEWAY}            (traçar rota até o gateway)

"""
        # Enviar informações no canal (apenas para o usuário)
        await interaction.response.send_message(info, ephemeral=True)
        
        # Enviar também por DM
        try:
            await interaction.user.send(info)
            if DEBUG_MODE:
                print("Informações da rede enviadas por DM")
                
        except Exception as e:
            log_error("Erro ao enviar informações da rede por DM", e)
            await interaction.followup.send("⚠️ Não foi possível enviar as informações por mensagem privada. Verifique se suas DMs estão abertas.", ephemeral=True)
    
    except Exception as e:
        log_error("Erro ao mostrar informações da rede", e)
        await interaction.response.send_message(f"❌ Erro ao obter informações da rede: {str(e)}", ephemeral=True)

@bot.command(name='clean_dm', help='Limpa mensagens do bot no chat privado')
async def clean_dm_cmd(ctx, num_messages=10):
    try:
        if isinstance(ctx.channel, discord.DMChannel):
            messages_to_delete = []
            async for message in ctx.channel.history(limit=50):
                if message.author == bot.user and len(messages_to_delete) < int(num_messages):
                    messages_to_delete.append(message)
            deleted_count = 0
            for message in messages_to_delete:
                try:
                    await message.delete()
                    deleted_count += 1
                    await asyncio.sleep(0.5)
                except:
                    pass
            
            temp_msg = await ctx.send(f"✅ {deleted_count} mensagens foram removidas da nossa conversa.")
            await asyncio.sleep(5)
            await temp_msg.delete()
        else:
            await ctx.send("Este comando só funciona em conversas privadas (DM).", delete_after=5)
    except Exception as e:
        log_error(f"Erro ao limpar o chat", e)
        await ctx.send("❌ Não foi possível limpar o chat.", delete_after=5)

@bot.command(name='scan_subnet', help='Verifica IPs livres em uma sub-rede')
async def scan_subnet_cmd(ctx, subnet_number):
    # Verificar se estamos em um DM
    is_dm = isinstance(ctx.channel, discord.DMChannel)
    
    try:
        # Converter para inteiro
        subnet = int(subnet_number)
        
        # Verificar se está no intervalo válido para uma rede /22 (0-3)
        if subnet < 0 or subnet > 3:
            await ctx.send("❌ Para uma rede /22 (255.255.252.0), o número da sub-rede deve estar entre 0 e 3.")
            return
        
        # Construir o CIDR da sub-rede
        network_cidr = f"{subnet}.0/24"
        
        # Mensagem inicial
        msg = await ctx.send(f"🔍 Escaneando a sub-rede {network_cidr}. Isso pode levar algum tempo...")
        
        # Verificar a rede
        network = ipaddress.ip_network(network_cidr, strict=False)
        
        # Lista para armazenar IPs livres
        free_ips = []
        
        # Lista para armazenar erros de verificação
        errors = []
        
        # Para redes menores, vamos limitar o número de IPs verificados simultaneamente
        batch_size = 25  # Verificar 25 IPs por vez (reduzido para não sobrecarregar)
        
        all_ips = list(network.hosts())
        total_batches = (len(all_ips) + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min((batch_num + 1) * batch_size, len(all_ips))
            
            # IPs a serem verificados neste lote
            batch_ips = all_ips[start_idx:end_idx]
            
            # Tarefas para verificar os IPs do lote
            tasks = [is_ip_available(ip) for ip in batch_ips]
            
            # Executar as tarefas do lote simultaneamente
            try:
                results = await asyncio.gather(*tasks)
                
                # Adicionar IPs livres à lista
                batch_free_ips = [str(ip) for ip, is_free in zip(batch_ips, results) if is_free]
                free_ips.extend(batch_free_ips)
                
                # Atualizar a mensagem de progresso
                progress = min(100, int((end_idx) / len(all_ips) * 100))
                await msg.edit(content=f"🔍 Escaneando a sub-rede {network_cidr}: {progress}% concluído... ({len(free_ips)} IPs livres encontrados até agora)")
            except Exception as e:
                error_msg = f"Erro ao verificar lote {batch_num+1}/{total_batches}: {str(e)}"
                errors.append(error_msg)
                log_error(error_msg, e)
                await ctx.send(f"⚠️ Erro ao verificar alguns IPs no lote {batch_num+1}/{total_batches}. Continuando...")
            
            # Pequena pausa entre os lotes para não sobrecarregar
            await asyncio.sleep(1.0)
        
        # Verificar se encontramos IPs livres
        if free_ips:
            # Mensagem final no canal
            await msg.edit(content=f"✅ Escaneamento concluído! Encontrados {len(free_ips)} IPs livres na sub-rede {network_cidr}. Os resultados foram enviados para sua mensagem privada.")
            
            # Adicionar mensagem sobre possíveis falsos positivos
            free_ips_text = '\n'.join(free_ips)
            if errors:
                free_ips_text += "\n\n⚠️ ATENÇÃO: Ocorreram alguns erros durante a verificação que podem afetar a precisão dos resultados."
                free_ips_text += "\nSempre confirme manualmente antes de usar um IP."
            
            # Enviar resultados por DM
            dm_success = await send_dm_results(
                ctx.author,
                f"IPs livres na sub-rede {network_cidr}",
                free_ips_text,
            )
            
            if not dm_success:
                await ctx.send("⚠️ Não foi possível enviar os resultados por mensagem privada. Verifique se suas DMs estão abertas.")
        else:
            await msg.edit(content=f"❌ Nenhum IP livre encontrado na sub-rede {network_cidr}")
        
    
    except ValueError:
        await ctx.send("❌ O número da sub-rede deve ser um número inteiro válido.")
    except Exception as e:
        await ctx.send(f"❌ Erro ao escanear a sub-rede: {str(e)}")

@bot.command(name='check_ip', help='Verifica se um IP específico está livre')
async def check_ip_cmd(ctx, ip_address):
    await check_ip(ctx.author, ip_address, ctx.message)

@bot.command(name='next_free', help='Encontra próximos IPs livres a partir de um endereço')
async def next_free_cmd(ctx, start_ip, count="5"):
    try:
        count_num = int(count)
        await find_next_free(ctx.author, start_ip, count_num, ctx.message)
    except ValueError:
        await ctx.send("❌ A quantidade deve ser um número inteiro válido.")

@bot.command(name='ip_details', help='Mostra detalhes completos sobre um IP')
async def ip_details_cmd(ctx, ip_address):
    await ip_details(ctx.author, ip_address, ctx.message)

@bot.command(name='network_info', help='Mostra informações da rede')
async def network_info_cmd(ctx):
    # Verificar se estamos em um DM
    is_dm = isinstance(ctx.channel, discord.DMChannel)
    
    try:
        # Obter informações da rede padrão
        network = ipaddress.ip_network(DEFAULT_NETWORK, strict=False)
        
        # Calcular informações da rede
        info = f"""
📊 **Informações da Rede**

🌐 **Rede:** {DEFAULT_NETWORK}
🔑 **Gateway:** {DEFAULT_GATEWAY}
🎭 **Máscara:** {network.netmask} (/{network.prefixlen})
📍 **Endereço de Rede:** {network.network_address}
📡 **Endereço de Broadcast:** {network.broadcast_address}
🔢 **Total de Endereços:** {network.num_addresses}
📈 **Faixa de IPs Utilizáveis:** {network.network_address + 1} até {network.broadcast_address - 1}

**Comandos CMD equivalentes:**

ipconfig /all                        (ver configuração de rede)
nslookup {DEFAULT_GATEWAY}           (resolver DNS do gateway)
tracert {DEFAULT_GATEWAY}            (traçar rota até o gateway)

"""
        # Enviar informações no canal
        await ctx.send(info)
        
        # Enviar também por DM
        try:
            await ctx.author.send(info)
        except Exception as e:
            log_error("Erro ao enviar informações da rede por DM", e)
            await ctx.send("⚠️ Não foi possível enviar as informações por mensagem privada. Verifique se suas DMs estão abertas.")
    
    except Exception as e:
        await ctx.send(f"❌ Erro ao obter informações da rede: {str(e)}")

@bot.event
async def on_ready():
    print(f'{bot.user.name} está conectado ao Discord!')
    print(f'Configurado para rede padrão: {DEFAULT_NETWORK}')
    print(f'Debug mode: {"ATIVADO" if DEBUG_MODE else "DESATIVADO"}')
    
    if check_dependencies():
        print("✅ Todas as dependências estão instaladas")
    
    try:
        synced = await bot.tree.sync()
        print(f"Sincronizados {len(synced)} comandos")
    except Exception as e:
        log_error("Erro ao sincronizar comandos slash", e)
        print("ERRO: Não foi possível sincronizar os comandos slash")


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    
    if message.content.startswith("!"):
        await bot.process_commands(message)
        return

    if message.reference and message.reference.resolved:
        ref_msg = message.reference.resolved

        if ref_msg.author == bot.user:
            try:
                if DEBUG_MODE:
                    print(f"\nUsuário {message.author.name} respondeu a uma mensagem do bot")
                    print(f"Conteúdo da resposta: {message.content}")
                    print(f"Conteúdo da mensagem original: {ref_msg.content}")

                if "Verificação de IP Específico" in ref_msg.content or "digite abaixo o IP que deseja verificar" in ref_msg.content:
                    # Extrair o IP da mensagem
                    ip_address = message.content.strip()
                    
                    if DEBUG_MODE:
                        print(f"Detectada resposta para verificação de IP: {ip_address}")
                    
                    # Verificar o IP
                    await check_ip(message.author, ip_address, message)
                    
                    # Tentar deletar a mensagem do usuário para manter a privacidade
                    try:
                        await message.delete()
                    except Exception as e:
                        log_error("Erro ao deletar mensagem do usuário", e)
                
                # Verificar se é uma resposta para obter detalhes de IP
                elif "Detalhar IP e Hostname" in ref_msg.content or "digite abaixo o IP que deseja analisar" in ref_msg.content:
                    # Extrair o IP da mensagem
                    ip_address = message.content.strip()
                    
                    if DEBUG_MODE:
                        print(f"Detectada resposta para detalhes de IP: {ip_address}")
                    
                    # Obter detalhes do IP
                    await ip_details(message.author, ip_address, message)
                    
                    # Tentar deletar a mensagem do usuário para manter a privacidade
                    try:
                        await message.delete()
                    except Exception as e:
                        log_error("Erro ao deletar mensagem do usuário", e)
                
                # Verificar se é uma resposta para encontrar próximos IPs livres
                elif "Encontrar Próximos IPs Livres" in ref_msg.content or "digite abaixo o IP inicial e quantidade" in ref_msg.content:
                    # Extrair o IP e quantidade da mensagem
                    parts = message.content.strip().split()
                    
                    if DEBUG_MODE:
                        print(f"Detectada resposta para próximos IPs livres: {message.content}")
                    
                    if len(parts) >= 1:
                        ip = parts[0]
                        count = 5
                        if len(parts) > 1 and parts[1].isdigit():
                            count = int(parts[1])
                        
                        # Encontrar próximos IPs livres
                        await find_next_free(message.author, ip, count, message)
                    
                    # Tentar deletar a mensagem do usuário para manter a privacidade
                    try:
                        await message.delete()
                    except Exception as e:
                        log_error("Erro ao deletar mensagem do usuário", e)
            
            except Exception as e:
                log_error("Erro ao processar resposta do usuário", e)
                await message.channel.send(f"❌ Erro ao processar sua mensagem: {str(e)}")


# Comando slash principal
@bot.tree.command(name="nettools", description="Abre o menu de ferramentas de rede")
async def nettools(interaction: discord.Interaction):
    try:
        if DEBUG_MODE:
            print(f"\nComando slash nettools invocado por {interaction.user.name}")
            
        await interaction.response.send_message(
            "🌐 **Ferramentas de Rede**\n\n"
            "Selecione uma ferramenta no menu abaixo para verificar sua rede:",
            view=SimpleMenuView(),
            ephemeral=False  # Menu principal visível para todos
        )
    except Exception as e:
        log_error("Erro ao processar comando slash nettools", e)
        await interaction.response.send_message("❌ Erro ao abrir o menu de ferramentas. Verifique o console para detalhes.", ephemeral=True)


# Comando de texto para iniciar o bot
@bot.command(name='nettools', help='Abre o menu de ferramentas de rede')
async def nettools_cmd(ctx):
    try:
        if DEBUG_MODE:
            print(f"\nComando texto nettools invocado por {ctx.author.name}")
            
        await ctx.send(
            "🌐 **Ferramentas de Rede**\n\n"
            "Selecione uma ferramenta no menu abaixo para verificar sua rede:",
            view=SimpleMenuView()
        )
    except Exception as e:
        log_error("Erro ao processar comando texto nettools", e)
        await ctx.send("❌ Erro ao abrir o menu de ferramentas. Verifique o console para detalhes.")


# Função principal para verificar ambiente e iniciar o bot
def main():
    print("==== Iniciando Bot de Inventário de Rede ====")
    print(f"Python: {platform.python_version()}")
    print(f"Sistema: {platform.system()} {platform.release()}")
    if check_dependencies():
        print("✅ Todas as dependências estão instaladas")
    print("Conectando ao Discord...")
    try:
        bot.run(TOKEN)
    except Exception as e:
        log_error("Erro ao iniciar o bot", e)
        print("\n❌ Não foi possível iniciar o bot. Verifique o token e a conexão com a internet.")
        if TOKEN is None or TOKEN == "":
            print("   O token do Discord não foi encontrado. Verifique o arquivo .env ou defina o token diretamente no código.")

if __name__ == "__main__":
    main()