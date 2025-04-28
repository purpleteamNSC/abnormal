import requests
import os
import time
import json
from datetime import datetime, timedelta, timezone

# Variveis de ambiente
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
DESTINATION_URL = os.getenv('DESTINATION_URL')
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 300))  # Intervalo padrão: 5 minutos
API_KEY_CLASS = os.getenv('API_KEY_CLASS')

# Função para gerar o filtro de data para o dia atual
def get_today_filter():
    now_utc = datetime.now(timezone.utc)
    start_of_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1) - timedelta(seconds=1)

    gte = start_of_day.isoformat().replace("+00:00", "Z")
    lte = end_of_day.isoformat().replace("+00:00", "Z")

    return f"filter=receivedTime gte {gte} lte {lte}"


# Arquivo para armazenar os IDs de ameaças já processadas
PROCESSED_IDS_FILE = "processed_threats.json"

# Cabeçalhos para autenticação na API
HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}"
}

# Carrega os IDs de ameaças já processados de um arquivo local
def load_processed_ids():
    if os.path.exists(PROCESSED_IDS_FILE):
        with open(PROCESSED_IDS_FILE, 'r') as f:
            return set(json.load(f))
    return set()

# Salva os IDs de ameaças processados em um arquivo local
def save_processed_ids(ids):
    with open(PROCESSED_IDS_FILE, 'w') as f:
        json.dump(list(ids), f)

# Faz a chamada para buscar ameaças na API
def fetch_threats():
    page = 1
    threats = []
    today_filter = get_today_filter()

    while True:
        url = f"https://api.abnormalplatform.com/v1/threats?pageNumber={page}&{today_filter}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            print(f"Erro ao buscar ameaças: {response.status_code} - {response.text}")
            break

        data = response.json()
        threats.extend(data.get("threats", []))

        # Verifica se há uma próxima página de resultados
        if not data.get("nextPageNumber"):
            break
        page = data["nextPageNumber"]

    return threats

# Faz a chamada para obter os detalhes de uma ameaça específica
def fetch_threat_details(threat_id):
    url = f"https://api.abnormalplatform.com/v1/threats/{threat_id}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erro ao buscar detalhes do threat {threat_id}: {response.status_code}")
        return None

# Envia os dados da ameaça para o endpoint de destino
def send_to_destination(threat_data):
    headers={
        "Authorization": API_KEY_CLASS
    }
    payload = { 
        "class":"abnormal", 
        "rawmsg": threat_data }
    
    response = requests.post(DESTINATION_URL, headers=headers, json=payload)
    if response.status_code == 200:
        print(f"Dados do threat {threat_data['threatId']} enviados com sucesso.")
        return True
    else:
        print(f"Erro ao enviar dados do threat {threat_data['threatId']}: {response.status_code} - {response.text}")
        return False

# Loop principal que executa o processo de forma contínua
def run():
    processed_ids = load_processed_ids()

    while True:
        print("Buscando novas ameaças...")
        threats = fetch_threats()

        for threat in threats:
            threat_id = threat["threatId"]
            if threat_id in processed_ids:
                continue  # Ignora ameaças já processadas

            details = fetch_threat_details(threat_id)
            if details and send_to_destination(details):
                processed_ids.add(threat_id)  # Marca a ameaça como processada
                save_processed_ids(processed_ids)

        print(f"Aguardando {POLL_INTERVAL} segundos para a próxima execução...")
        time.sleep(POLL_INTERVAL)

# Ponto de entrada do script
if __name__ == "__main__":
    run()
