# N1---2B---IDS-Intrusion-Detection-System-

Explicação Geral do Código
Esse código é um exemplo de detecção de ataques SYN flood, que ocorre quando um cliente envia múltiplos pacotes SYN para o servidor para tentar sobrecarregar o sistema.

Configuração do socket: Captura pacotes TCP com um socket bruto (raw socket).
Decodificação e contagem de pacotes SYN: Cada vez que o código detecta uma flag SYN, ele incrementa a contagem de conexões daquele IP.
Bloqueio automático: Se um IP envia 10 ou mais pacotes SYN em um intervalo curto (o padrão de ataque), ele é bloqueado com uma regra iptables para rejeitar pacotes futuros.
Observações e Considerações
Este é um exemplo básico de código de defesa contra SYN flood. Em um ambiente de produção, o ideal seria usar outras técnicas de detecção e mitigação mais robustas. Além disso, é sempre importante testar rigorosamente em um ambiente seguro para evitar bloqueios acidentais.
