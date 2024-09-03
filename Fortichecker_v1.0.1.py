import re
import sys
import requests
import argparse
from tqdm import tqdm
from colorama import Fore, Style, init
import os
import csv

# Inicializa colorama para Windows
init(autoreset=True)

def display_banner():
    banner = f"""
{Fore.GREEN}

 _____ ______  ______            _    _        _                  _               
|_   _|| ___ \ |  ___|          | |  (_)      | |                | |              
  | |  | |_/ / | |_  ___   _ __ | |_  _   ___ | |__    ___   ___ | | __ ___  _ __ 
  | |  |  __/  |  _|/ _ \ | '__|| __|| | / __|| '_ \  / _ \ / __|| |/ // _ \| '__|
 _| |_ | |     | | | (_) || |   | |_ | || (__ | | | ||  __/| (__ |   <|  __/| |   
 \___/ \_|     \_|  \___/ |_|    \__||_| \___||_| |_| \___| \___||_|\_\\___||_|   
                                                                                 
  // IP Malice Checker                                                   
 //  by: Luis Sergent (Aka. Savalone)                                    
//_______________________________________________________________________
{Style.RESET_ALL}
Description: Analiza un archivo de log para detectar IPs maliciosas usando la API de AbuseIPDB.
"""
    print(banner)

def extract_ips(log_file):
    try:
        with open(log_file, 'r') as file:
            log_data = file.read()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: El archivo {log_file} no se encuentra.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error al leer el archivo {log_file}: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Excluye IPs 0.0.0.0 y 127.0.0.1
    ips = re.findall(r'srcip.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_data)
    filtered_ips = [ip for ip in set(ips) if ip not in ['0.0.0.0', '127.0.0.1']]
    return sorted(filtered_ips)

def check_ip_abuse(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': ''
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Lanza una excepción para códigos de estado 4xx/5xx
        data = response.json()['data']
        return {
            'ip': data['ipAddress'],
            'country': data['countryName'],
            'reports': data['totalReports'],
            'abuse_confidence': data['abuseConfidenceScore']
        }
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
            print(f"{Fore.RED}Error: API key incorrecta o no autorizada.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Error HTTP al consultar la IP {ip}: {http_err}{Style.RESET_ALL}")
        sys.exit(1)
    except requests.exceptions.RequestException as req_err:
        print(f"{Fore.RED}Error de conexión al consultar la IP {ip}: {req_err}{Style.RESET_ALL}")
        return None
    except KeyError:
        print(f"{Fore.RED}Error al procesar la respuesta para la IP {ip}. Verifica la estructura de la respuesta.{Style.RESET_ALL}")
        return None

def save_malicious_ips(malicious_ips, raw_output_file):
    detailed_output_file = f"{os.path.splitext(raw_output_file)[0]}.details"

    try:
        with open(raw_output_file, 'w') as raw_file, open(detailed_output_file, 'w') as detailed_file:
            for ip_data in malicious_ips:
                raw_file.write(f"{ip_data['ip']}\n")
                detailed_file.write(f"IP: {ip_data['ip']}, País: {ip_data['country']}, Reportes: {ip_data['reports']}, Reputacion: {ip_data['abuse_confidence']}%\n\n")
    except IOError as e:
        print(f"{Fore.RED}Error al escribir en el archivo: {e}{Style.RESET_ALL}")
        sys.exit(1)

def save_ips_to_csv(legit_ips, malicious_ips, detailed_data, output_file):
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Escribir el encabezado de las IPs
            writer.writerow(["IP Legítimas", "IP Maliciosas"])
            
            # Alinear IPs legítimas y maliciosas
            max_len = max(len(legit_ips), len(malicious_ips))
            for i in range(max_len):
                legit_ip = legit_ips[i]['ip'] if i < len(legit_ips) else ''
                malicious_ip = malicious_ips[i]['ip'] if i < len(malicious_ips) else ''
                writer.writerow([legit_ip, malicious_ip])
            
            # Espacio entre secciones
            writer.writerow([])
            
            # Encabezado de los detalles
            writer.writerow(["Detalles de las IPs"])
            
            # Ordenar detalles: primero confiables, luego maliciosas
            sorted_details = sorted(detailed_data.items(), key=lambda item: item[1]['abuse_confidence'])
            
            for ip, details in sorted_details:
                detail_string = f"IP: {ip}, Ubicación: {details['country']}, Reportes: {details['reports']}, Reputación: {details['abuse_confidence']}%"
                if details['abuse_confidence'] > 0:
                    detail_string += " [Maliciosa]"
                else:
                    detail_string += " [Confiable]"
                writer.writerow([detail_string])

        print(f"{Fore.GREEN}Datos guardados correctamente en {output_file}{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}Error al escribir en el archivo: {e}{Style.RESET_ALL}")
        sys.exit(1)


def main():
    default_api = 'API_KEY'
    parser = argparse.ArgumentParser(description='Analiza un archivo de log para IPs maliciosas.')
    parser.add_argument('log_file', help='Archivo de log a analizar')
    parser.add_argument('-o', '--output', help='Archivo de salida para IPs maliciosas (raw)', default='malicious_ip_summary')
    parser.add_argument('-k', '--api-key', help='API Key de AbuseIPDB', default=default_api)
    parser.add_argument('--csv', help='Genera un archivo CSV con el resultado', action='store_true')

    args = parser.parse_args()
    
    display_banner()
    
    ips = extract_ips(args.log_file)
    malicious_ips = []
    legit_ips = []
    detailed_data = {}

    print(f"{Fore.CYAN}Analizando IPs...{Style.RESET_ALL}")

    for ip in tqdm(ips, desc="Procesando", bar_format="{l_bar}{bar}{r_bar}", colour="green"):
        ip_data = check_ip_abuse(ip, args.api_key)
        if ip_data:
            detailed_data[ip] = ip_data
            if ip_data['abuse_confidence'] > 0:
                malicious_ips.append(ip_data)
            else:
                legit_ips.append(ip_data)

    if args.csv:
        output_csv = f"{os.path.splitext(args.output)[0]}.csv"
        save_ips_to_csv(legit_ips, malicious_ips, detailed_data, output_csv)
    else:
        if malicious_ips:
            save_malicious_ips(malicious_ips, args.output)
            detailed_output_file = f"{os.path.splitext(args.output)[0]}.details"
            print(f"{Fore.GREEN}IPs maliciosas guardadas en {args.output} y {detailed_output_file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No se encontraron IPs maliciosas.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

