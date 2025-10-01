"""
Analisador de Tráfego de Rede com Agregação em Janelas de Tempo
---------------------------------------------------------------

Este script captura pacotes de rede em uma interface especificada,
agrega os dados em intervalos fixos (5 segundos por padrão) e exporta
os resultados para um arquivo CSV. Os dados armazenados incluem
volume de bytes e número de pacotes de entrada e saída, agrupados
por cliente (IP) e protocolo.

Utilização:
    - Execute com privilégios de root/admin para capturar pacotes.
    - Ajuste a variável INTERFACE para a interface de rede correta.
    - O script gerará periodicamente o arquivo "traffic_data.csv".
    - Esse CSV pode ser consumido por Excel para dashboards dinâmicos.

Autores:
01: Othon Flávio Alves de Sales - 2312130178
02: Mariana Paiva de Souza Moreira - 2312130137
"""

#Executar primeiro:
# Instala o pacote de desenvolvimento libpcap que o Scapy precisa
# !apt-get update && apt-get install -y libpcap-dev

#Após isso, execute:
# !pip install scapy

#Algoritmo:
import scapy.all as scapy
import time
import collections
import csv
import threading
from datetime import datetime

# ==============================
# Configurações do Analisador
# ==============================

# Intervalo de agregação em segundos (default = 5)
AGGREGATION_INTERVAL = 5

# Estrutura de dados para tráfego agregado:
# Chave: (timestamp_interval, client_ip, protocol)
# Valor: dicionário contendo bytes/packets de entrada e saída
aggregated_traffic = collections.defaultdict(lambda: {
    'bytes_in': 0,
    'bytes_out': 0,
    'packets_in': 0,
    'packets_out': 0
})

# Lock garante acesso seguro ao dicionário em ambiente multithread
traffic_lock = threading.Lock()

# Interface de rede monitorada (ajuste conforme seu ambiente)
INTERFACE = "eth0"  # Exemplo: 'eth0', 'wlan0', 'Ethernet'

# Arquivo CSV de saída
CSV_FILENAME = "traffic_data.csv"

# Cabeçalho do CSV
CSV_HEADERS = ["Timestamp", "Client_IP", "Protocol", "Bytes_In", "Bytes_Out", "Packets_In", "Packets_Out"]


# ==============================
# Funções Auxiliares
# ==============================

def get_local_ip():
    """
    Obtém o IP associado à interface de rede monitorada.

    Returns:
        str: Endereço IP da interface especificada.
    """
    try:
        return scapy.get_if_addr(INTERFACE)
    except Exception:
        print(f"AVISO: Não foi possível obter o IP da interface {INTERFACE}. Usando fallback.")
        # Substitua pelo IP do servidor alvo em seu ambiente
        return "192.168.1.100"


LOCAL_IP = get_local_ip()
print(f"IP do Servidor Alvo detectado: {LOCAL_IP}")


def process_packet(packet):
    """
    Processa um pacote de rede, determinando se é de entrada ou saída,
    classificando pelo protocolo e acumulando em uma janela de tempo.

    Args:
        packet (scapy.Packet): Pacote capturado pela interface de rede.
    """
    global aggregated_traffic

    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        # Identificação do protocolo
        protocol = "UNKNOWN"
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
        elif packet.haslayer(scapy.ARP):
            # ARP descartado: não faz parte da análise de camada 3
            return

        # Alinhamento do timestamp para a janela de agregação
        current_time = int(time.time())
        timestamp_interval = (current_time // AGGREGATION_INTERVAL) * AGGREGATION_INTERVAL

        with traffic_lock:
            # Caso 1: Tráfego de saída do servidor alvo
            if src_ip == LOCAL_IP:
                client_ip = dst_ip
                key = (timestamp_interval, client_ip, protocol)

                aggregated_traffic[key]['bytes_out'] += packet_size
                aggregated_traffic[key]['packets_out'] += 1

            # Caso 2: Tráfego de entrada para o servidor alvo
            elif dst_ip == LOCAL_IP:
                client_ip = src_ip
                key = (timestamp_interval, client_ip, protocol)

                aggregated_traffic[key]['bytes_in'] += packet_size
                aggregated_traffic[key]['packets_in'] += 1


def start_sniffing():
    """
    Inicia a captura de pacotes em tempo real na interface definida.
    """
    print(f"Iniciando a captura na interface {INTERFACE}...")
    try:
        scapy.sniff(iface=INTERFACE, prn=process_packet, store=0, filter="ip")
    except Exception as e:
        print(f"ERRO FATAL: {e}")
        print("Sugestão: execute com sudo/admin.")


def write_to_csv():
    """
    Thread responsável por escrever periodicamente os dados agregados
    no arquivo CSV, a cada intervalo definido.
    """
    global aggregated_traffic

    # Inicializa o CSV com cabeçalho
    with open(CSV_FILENAME, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(CSV_HEADERS)

    while True:
        time.sleep(AGGREGATION_INTERVAL)

        current_time = int(time.time())
        # Seleciona apenas o intervalo que acabou de fechar
        timestamp_to_process = (current_time // AGGREGATION_INTERVAL) * AGGREGATION_INTERVAL - AGGREGATION_INTERVAL

        data_to_write = []
        with traffic_lock:
            keys_to_remove = []
            for key, values in aggregated_traffic.items():
                if key[0] == timestamp_to_process:
                    timestamp_dt = datetime.fromtimestamp(key[0])
                    data_to_write.append([
                        timestamp_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        key[1],  # Client_IP
                        key[2],  # Protocol
                        values['bytes_in'],
                        values['bytes_out'],
                        values['packets_in'],
                        values['packets_out']
                    ])
                    keys_to_remove.append(key)

            # Limpa entradas já processadas
            for key in keys_to_remove:
                del aggregated_traffic[key]

        # Grava no CSV
        if data_to_write:
            try:
                with open(CSV_FILENAME, 'a', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerows(data_to_write)
                print(f"Dados agregados ({datetime.fromtimestamp(timestamp_to_process).strftime('%H:%M:%S')}) gravados em {CSV_FILENAME}")
            except Exception as e:
                print(f"Erro ao escrever no CSV: {e}")


# ==============================
# Execução Principal
# ==============================
if __name__ == "__main__":
    # Thread de captura de pacotes
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Thread de escrita CSV
    csv_writer_thread = threading.Thread(target=write_to_csv)
    csv_writer_thread.daemon = True
    csv_writer_thread.start()

    print(f"Analisador iniciado | Intervalo: {AGGREGATION_INTERVAL}s")
    print(f"Servidor alvo: {LOCAL_IP} | Saída: {CSV_FILENAME}")
    print("Pressione Ctrl+C para encerrar.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExecução interrompida. CSV finalizado.")
