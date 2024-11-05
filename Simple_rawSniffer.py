# Importa as bibliotecas necessárias
import socket
import struct
import time
import iptc
import os

# Função para bloquear um endereço IP usando o iptables
def block_ip(ip_address):
    # Cria uma nova regra no iptables para bloquear o IP
    rule = iptc.Rule()
    rule.src = ip_address
    rule.target = iptc.Target(rule, "DROP")

    # Adiciona a regra à cadeia de INPUT, que bloqueia pacotes de entrada
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

# Dicionários para armazenar contagens de IPs e uma lista de IPs bloqueados
ips = {}
ips_blocked = []
start_time = time.time()  # Tempo inicial para cálculo de intervalo de 10 segundos

# Função para decodificar flags TCP. Neste caso, verifica apenas a flag SYN
def decode_tcp_flags(flags):
    tcp_flags = {
        'SYN': (flags & 0x02) != 0,  # 0000 0010 - Bit correspondente à flag SYN
    }
    return tcp_flags

# Cria um socket raw (bruto) para capturar pacotes TCP
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

print("Aguardando pacotes TCP...")

# Loop principal para capturar e processar pacotes
while True:
    # Captura um pacote da rede
    packet, addr = raw_socket.recvfrom(65565)

    # Extrai o cabeçalho IP (20 primeiros bytes) e o endereço IP de origem
    ip_header = packet[0:20]
    ip_origin = socket.inet_ntoa(ip_header[12:16])

    # Extrai o cabeçalho TCP (20 bytes seguintes ao cabeçalho IP) e os flags TCP
    tcp_header = packet[20:40]
    flags = tcp_header[13]  # O byte 13 contém as flags TCP
    syn_flag = flags & 0x02  # Verifica se a flag SYN está ativa
    time_elapsed = time.time() - start_time  # Calcula o tempo decorrido desde o início

    # Zera o dicionário de contagem de IPs a cada 10 segundos
    if time_elapsed >= 10:
        ips = {}

    # Se o pacote contém uma flag SYN, ele incrementa a contagem de requisições daquele IP
    if syn_flag:
        if ip_origin in ips:
            ips[ip_origin] += 1
        else:
            ips[ip_origin] = 1

        # Exibe o IP e o número de tentativas de conexão
        print(f"REQUISICAO => {ip_origin}-numero:{ips[ip_origin]}")
        
        # Bloqueia o IP se ele fez 10 ou mais tentativas de conexão (SYN flood)
        if ips[ip_origin] >= 10:
            print(f"bloqueado - {ip_origin}")
            ips_blocked.append(ip_origin)
            # Adiciona uma regra no iptables para bloquear o IP de origem
            os.system(f"iptables -A INPUT -s {ip_origin} -j DROP")
