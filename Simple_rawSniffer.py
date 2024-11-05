import socket
import struct
import time
import iptc
import os

def block_ip(ip_address):
    # Create a new rule
    rule = iptc.Rule()
    rule.src = ip_address
    rule.target = iptc.Target(rule, "DROP")

    # Add the rule to the INPUT chain
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

ips = {}
ips_blocked = []
start_time = time.time()

def decode_tcp_flags(flags):
    tcp_flags = {
        'SYN': (flags & 0x02) != 0,  # 0000 0010
    }
    return tcp_flags
# Crie um socket raw Ethernet para capturar pacotes
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

print("Aguardando pacotes TCP...")

while True:
    # Capture um pacote Ethernet
    packet, addr = raw_socket.recvfrom(65565)

    ip_header = packet[0:20]
    ip_origin = socket.inet_ntoa(ip_header[12:16])

    tcp_header = packet[20:40]
    flags = tcp_header[13]
    syn_flag = flags & 0x02
    time_elapsed = time.time() - start_time

    
    if time_elapsed >= 10:
        ips = {}

    if syn_flag:
        if ip_origin in ips:
            ips[ip_origin] += 1
        else:
            ips[ip_origin] = 1

        print(f"REQUISICAO => {ip_origin}-numero:{ips[ip_origin]}")
        if ips[ip_origin] >= 10:
            print(f"bloqueado - {ip_origin}")
            ips_blocked.append(ip_origin)
            os.system(f"iptables -A INPUT -s {ip_origin} -j DROP")



	
    """
    # Analise o cabeçalho Ethernet
    eth_header = packet[:14]
    eth_payload = packet[14:]

    eth_dest_mac, eth_src_mac, eth_type = struct.unpack("!6s6sH", eth_header)


    # Verificar se o pacote é IPv4 (EtherType 0x0800)
    if eth_type == 0x0800:
        ip_header = eth_payload[:20]
        ip_version, ip_tos, ip_length, ip_id, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack("!BBHHHBBH4s4s", ip_header)

       

        # Verificar se o protocolo é TCP (protocolo 6) ou UDP (protocolo 17)
        if ip_protocol == 6:
            if ip_protocol == 6:
                tcp_header = eth_payload[20:33]
                src_port, dest_port, sequence, ack_num, offset_flags = struct.unpack("!HHIIB", tcp_header)
                offset = (offset_flags >> 4) * 4
                if (offset_flags & 0x02) == 0:
                    continue

                print("Cabeçalho IP:")
                print(f"Endereço de origem: {socket.inet_ntoa(ip_src)}")
                print(f"Endereço de destino: {socket.inet_ntoa(ip_dest)}")
                print(f"Protocolo: {ip_protocol}")
                print("--------------------")

                print("Cabeçalho TCP:")
                print(f"Porta de origem: {src_port}")
                print(f"Porta de destino: {dest_port}")
                print(f"Número de Sequência: {sequence}")
                print(f"Número de Ack: {ack_num}")
                print(f"flag: {decode_tcp_flags(offset_flags)}")
                print("--------------------")
                if socket.inet_ntoa(ip_src) in ips:
                    ips[socket.inet_ntoa(ip_src)] += 1
                else:
                    ips[socket.inet_ntoa(ip_src)] = 1

                if ips[socket.inet_ntoa(ip_src)] >= 100:
                    ips_blocked.append(socket.inet_ntoa(ip_src))
                    #block_ip(ips_blocked[0])

                time_elapsed = time.time() - start_time
                if time_elapsed >= 10:
                    start_time = time.time()
                    ips = {}
"""


'''
O uso desses símbolos, como "!BBHHHBBH4s4s", está relacionado ao empacotamento e desempacotamento de dados em uma estrutura de pacote em uma comunicação de rede ao trabalhar com sockets raw em Python. Essa sequência de caracteres é uma string de formato que descreve como os dados brutos devem ser interpretados ou construídos.

Aqui está o que cada símbolo significa:

- `!`: Indica que os dados devem ser interpretados na ordem nativa do host (endianess). Isso significa que os dados serão lidos ou escritos na ordem em que são representados na arquitetura do computador em que o código está sendo executado.

- `BBHHHBBH4s4s`: Essa parte da string de formato descreve a estrutura específica dos dados no pacote. Cada letra ou símbolo corresponde a um campo de dados na estrutura. Aqui está uma correspondência:

  - `B`: Um byte (8 bits).
  - `H`: Um short integer (16 bits).
  - `4s`: Uma sequência de 4 bytes (32 bits) interpretada como uma string.
  - `4s`: Outra sequência de 4 bytes (32 bits) interpretada como uma string.

A sequência "!BBHHHBBH4s4s" pode ser usada para descrever um pacote de dados que consiste em:

- Um byte (B)
- Outro byte (B)
- Um short integer (H)
- Um short integer (H)
- Um short integer (H)
- Um byte (B)
- Outro byte (B)
- Um short integer (H)
- Duas sequências de 4 bytes (4s e 4s)

Essa sequência de formato é útil ao lidar com a análise de pacotes em uma comunicação de rede de baixo nível, como em sockets raw, onde você precisa especificar como os dados brutos são organizados para extrair informações significativas deles ou criar pacotes para envio. Cada símbolo na sequência de formato corresponde a um campo de dados específico no pacote.
'''

