# N1---2B---IDS-Intrusion-Detection-System-

EXPLICAÇÃO GERAL DO CÓDIGO:

Esse código é um exemplo de detecção de ataques SYN flood, que ocorre quando um cliente envia múltiplos pacotes SYN para diferentes servidores com o objetivo de sobrecarregar um dos sistemas, assim como poder ser visualizado na imagem abaixo:
![image](https://github.com/user-attachments/assets/8d77fa2c-1cc3-4fcf-bc9d-6e3ffcede5c0)



Configuração do socket: Captura pacotes TCP com um socket bruto (raw socket).
Decodificação e contagem de pacotes SYN: Cada vez que o código detecta uma flag SYN, ele incrementa a contagem de conexões daquele IP.
Bloqueio automático: Se um IP envia 10 ou mais pacotes SYN em um intervalo curto (o padrão de ataque), ele é bloqueado com uma regra iptables para rejeitar pacotes futuros.
Observações e Considerações
Este é um exemplo básico de código de defesa contra SYN flood. Em um ambiente de produção, o ideal seria usar outras técnicas de detecção e mitigação mais robustas. Além disso, é sempre importante testar rigorosamente em um ambiente seguro para evitar bloqueios acidentais.
