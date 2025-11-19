import os
import psutil
import clamd

# Lista de procesos maliciosos conocidos o nombres sospechosos
procesos_maliciosos = [
    "malware.exe", "virus.exe", "trojan.exe", "spyware.exe", "ransomware.exe",
    "explorer_fake.exe", "svchost_fake.exe", "taskmgr_fake.exe"
]

# Lista de rutas sospechosas (ampliar con rutas comunes de ataques)
rutas_sospechosas = [
    "C:/Temp", "C:/Users/usuario/AppData/Local/Temp", "C:/Windows/System32/fake/",
    "/tmp", "/var/tmp", "/home/user/.malicious/"
]

# Lista de extensiones maliciosas comunes
extensiones_peligrosas = [".exe", ".bat", ".vbs", ".scr", ".dll"]

# Función para monitorear procesos y eliminar los que coincidan con la lista negra
def monitorear_procesos():
    for proceso in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
        try:
            pid = proceso.info['pid']
            nombre_proceso = proceso.info['name']
            ruta_exe = proceso.info['exe']
            cpu_uso = proceso.info['cpu_percent']

            # Imprimir detalles del proceso
            print(f"PID: {pid} | Nombre: {nombre_proceso} | Uso de CPU: {cpu_uso}% | Ruta: {ruta_exe}")

            # Regla 1: Si el nombre del proceso está en la lista negra
            if nombre_proceso in procesos_maliciosos:
                print(f"¡Alerta! Proceso malicioso detectado: {nombre_proceso} (PID: {pid})")
                psutil.Process(pid).terminate()

            # Regla 2: Si el proceso se está ejecutando desde una ruta sospechosa
            if any(ruta in ruta_exe for ruta in rutas_sospechosas):
                print(f"¡Alerta! Proceso ejecutado desde una ruta sospechosa: {ruta_exe}")
                psutil.Process(pid).terminate()

            # Regla 3: Si el archivo ejecutable tiene una extensión peligrosa
            if any(ruta_exe.endswith(ext) for ext in extensiones_peligrosas):
                print(f"¡Alerta! El proceso está usando un archivo con una extensión peligrosa: {ruta_exe}")
                psutil.Process(pid).terminate()

            # Regla 4: Si el uso de CPU es extremadamente alto
            if cpu_uso > 80:  # Umbral ajustable
                print(f"¡Alerta! Uso de CPU elevado por el proceso {nombre_proceso} (PID: {pid})")
                psutil.Process(pid).terminate()

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Función para escanear archivos con ClamAV
def escanear_archivo(ruta_archivo):
    try:
        cd = clamd.ClamdUnixSocket()
        resultado = cd.scan(ruta_archivo)

        if resultado:
            print(f"Resultado del escaneo de {ruta_archivo}: {resultado}")
        else:
            print(f"Archivo limpio: {ruta_archivo}")

    except Exception as e:
        print(f"Error al escanear el archivo {ruta_archivo}: {e}")

# Monitoreo combinado con escaneo de archivos maliciosos
def monitorear_y_escanear_procesos():
    for proceso in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proceso.info['pid']
            nombre_proceso = proceso.info['name']
            ruta_exe = proceso.info['exe']

            print(f"Monitoreando proceso: {nombre_proceso} (PID: {pid})")

            # Escanea el archivo ejecutable del proceso usando ClamAV
            escanear_archivo(ruta_exe)

            # Aplica reglas para detectar si el proceso es malicioso
            monitorear_procesos()

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Ejecutar monitoreo y escaneo
monitorear_y_escanear_procesos()