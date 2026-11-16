import requests
import time

URL_API = "http://127.0.0.1:5000/api/webhook/alerta"

ataques_simulados = [
    {
        "titulo": "Detección de Ransomware LockBit en nodo de archivos",
        "categoria": "Malware",
        "activo": "Servidor Campus Virtual Moodle"
    },
    {
        "titulo": "Campaña Phishing suplantando portal de matrículas",
        "categoria": "Phishing",
        "activo": "Correo Institucional @unadvirtual.edu.co"
    }
]

print("Iniciando simulación de ciberataques desde Cyber Range...")
for ataque in ataques_simulados:
    resp = requests.post(URL_API, json=ataque)
    print(f"[+] Alerta enviada: {ataque['titulo']} -> Respuesta API: {resp.json()}")
    time.sleep(2)