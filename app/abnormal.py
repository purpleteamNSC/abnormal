import requests
import urllib3
import os
import time
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv


# Carrega os arquivos de .env
load_dotenv()
# Resolve os problemas de certificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
DESTINATION_URL = os.getenv('DESTINATION_URL')
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 300))  # padrão: 5 minutos
API_KEY_CLASS = os.getenv('API_KEY_CLASS')

# Arquivo para armazenar os threats já processados
PROCESSED_IDS_FILE = "processed_threats.json"

HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}"
}

# Função para gerar logs
def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}"
    print(log_entry)
    with open("abnormal.log", "a") as log_file:
        log_file.write(log_entry + "\n")

# pega as datas
def get_today_filter():
    now_utc = datetime.now(timezone.utc)
    start_of_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1) - timedelta(seconds=1)

    gte = start_of_day.isoformat().replace("+00:00", "Z")
    lte = end_of_day.isoformat().replace("+00:00", "Z")

    return f"filter=receivedTime gte {gte} lte {lte}"

# Carrega ou inicializa os threats processados
def load_processed_ids():
    if os.path.exists(PROCESSED_IDS_FILE):
        with open(PROCESSED_IDS_FILE, 'r') as f:
            log_message("Processed IDs file loaded successfully.")
            return set(json.load(f))
    log_message("No processed IDs file found. Starting fresh.")
    return set()

# Salva os threats processados no arquivo
def save_processed_ids(ids):
    max_file_size = 5 * 1024 * 1024  # 5 MB
    if os.path.exists(PROCESSED_IDS_FILE) and os.path.getsize(PROCESSED_IDS_FILE) >= max_file_size:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        rotated_file = f"{PROCESSED_IDS_FILE}.{timestamp}.bak"
        os.rename(PROCESSED_IDS_FILE, rotated_file)
        log_message(f"Processed IDs file rotated to {rotated_file}.")
    
    with open(PROCESSED_IDS_FILE, 'w') as f:
        json.dump(list(ids), f)
    log_message("Processed IDs saved successfully.")

# Faz chamada 1 para buscar ameaças
def fetch_threats():
    page = 1
    threats = []
    today_filter = get_today_filter()

    while True:
        url = f"https://api.abnormalplatform.com/v1/threats?pageNumber={page}&{today_filter}"
        response = requests.get(url, headers=HEADERS, verify=False)
        if response.status_code != 200:
            log_message(f"Error fetching threats: {response.status_code} - {response.text}", level="ERROR")
            break

        data = response.json()
        threats.extend(data.get("threats", []))
        log_message(f"Fetched {len(data.get('threats', []))} threats from page {page}.")

        if not data.get("nextPageNumber"):
            break
        page = data["nextPageNumber"]

    log_message(f"Total threats fetched: {len(threats)}.")
    return threats

# Faz chamada 2 para obter os detalhes da ameaça
def fetch_threat_details(threat_id):
    url = f"https://api.abnormalplatform.com/v1/threats/{threat_id}"
    response = requests.get(url, headers=HEADERS, verify=False)
    if response.status_code == 200:
        log_message(f"Details fetched for threat ID {threat_id}.")
        return response.json()
    else:
        log_message(f"Error fetching details for threat ID {threat_id}: {response.status_code}", level="ERROR")
        return None

# Envia os dados para o helix
def send_to_destination(threat_data):
    headers = {
        "Authorization": API_KEY_CLASS
    }
    
    response = requests.post(DESTINATION_URL, headers=headers, json=threat_data['messages'], verify=False)
    if response.status_code == 200:
        log_message(f"Threat data {threat_data['threatId']} sent successfully.")
        return True
    else:
        log_message(f"Error sending threat data {threat_data['threatId']}: {response.status_code} - {response.text}", level="ERROR")
        return False

# Loop principal
def run():
    log_message("Application started.")
    processed_ids = load_processed_ids()

    while True:
        log_message("Fetching new threats...")
        threats = fetch_threats()

        for threat in threats:
            threat_id = threat["threatId"]
            if threat_id in processed_ids:
                log_message(f"Threat ID {threat_id} already processed. Skipping.")
                continue

            details = fetch_threat_details(threat_id)
            if details and send_to_destination(details):
                processed_ids.add(threat_id)
                save_processed_ids(processed_ids)
                time.sleep(5)

        log_message(f"Waiting {POLL_INTERVAL} seconds for the next execution...")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
