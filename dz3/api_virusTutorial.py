import requests
import hashlib

API_KEY = 'your_virustotal_api_key' # нет ключа для API, но его нужно вставить для выполнения условий

url = 'https://www.virustotal.com/api/v3/files/'

def upload_file(file_path):
    headers = {
        'x-apikey': API_KEY
    }

    with open(file_path, 'rb') as file:
        files = {
            'file': (file_path, file)
        }
        
        response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            print("Файл успешно загружен на анализ.")
            return response.json()
        else:
            print(f"Ошибка при загрузке файла: {response.status_code}")
            return None

def get_report(file_hash):
    headers = {
        'x-apikey': API_KEY
    }

    response = requests.get(url + file_hash, headers=headers)

    if response.status_code == 200:
        print("Результаты анализа получены.")
        return response.json()
    else:
        print(f"Ошибка при получении отчета: {response.status_code}")
        return None


file_path = '../Recovery'
result = upload_file(file_path)


if result:
    file_hash = result['data']['id']
    report = get_report(file_hash)
    if report:
        print(report)
