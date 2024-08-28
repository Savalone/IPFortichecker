# IPFortichecker
Herramienta para analizar logs exportados de fortigate y analizar las ip mediante el API de AbuseIP

# Como funciona? 

La herramienta lee el archivo proporcionado como argumento y filtra por las direcciones IP de origen mediante expresiones regulares, luego realiza la peticion a la API de abuseIP para verificar la reputacion de la direccion IP, si se detecta maliciosa la agrega a una lista de direcciones maliciosas, al terminar de ejecutarse se generaran 2 archivos, en el primero se encontrara la lista de las direcciones IP, y en el otro los detalles arrojados por abuseIP.


![Captura de pantalla 2024-08-28 104325](https://github.com/user-attachments/assets/0cdecac2-bb9b-4f3e-99e8-f868d1fc1291)
![Captura de pantalla 2024-08-28 104453](https://github.com/user-attachments/assets/f7640fc3-a797-4313-af74-5590df93652e)

# Uso

## Uso basico
```bash
python3 fortichecker.py Archivo.log
```

## Opciones
```bash
python3 fortichecker.py -o Nombre_output Archivo.log

python3 fortichecker.py -k API_KEY Archivo.log
```

# Variables

```python
def main():
    default_api = 'API-KEY' # En esta seccion puedes poner tu api-key para que la use por defecto  
    parser = argparse.ArgumentParser(description='Analiza un archivo de log para encontrar IPs maliciosas.')
    parser.add_argument('log_file', help='Archivo de log a analizar')
    parser.add_argument('-o', '--output', help='Archivo de salida raw para IPs maliciosas', default='malicious_ip_summary') # Aqui puedes modificar el nombre del archivo generado
    parser.add_argument('-k', '--api-key', help='API Key de AbuseIPDB', default=default_api)
```







