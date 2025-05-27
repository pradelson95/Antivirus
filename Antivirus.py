import hashlib
from virus_total_apis import PublicApi 
from APi import API_KEY, AudioNotFoundError
import win10toast
from playsound import playsound
import threading
import os 



API = PublicApi(API_KEY)  # Crear una instancia de la API de VirusTotal con la clave API proporcionada

try:
    

    with open("archivo.txt", "rb") as file:
        contenido = file.read()
        file_hash = hashlib.md5(contenido).hexdigest() # Calcular el hash SHA-256 del archivo
        response = API.get_file_report(file_hash)  # Obtener el informe del archivo desde VirusTotalapi
        

    if response["response_code"] == 200:  
        results = response.get("results", {})

        if results.get("response_code") == 1:
            positives = results.get("positives", 0)  # Número de motores antivirus que detectaron el archivo como malicioso
            if positives > 0:
                playsound("sonido 1.mp3")
        
                threading.Thread(target=win10toast.ToastNotifier().show_toast, args=("Alerta de Virus", f"El archivo {file_hash} ha sido detectado como malicioso por {positives} motores antivirus.", "sonido 1.mp3", 10)).start()
                os.remove("archivo.txt")
                #print(Fore.LIGHTRED_EX + f"El archivo {file_hash} ha sido detectado como malicioso por {positives} motores antivirus.")
            else:
                print("El archivo no se ha detectado como maalicioso")
        else:
            print("No se ha encontrado nada en la base de datse de VirusTotal para el archivo calculadora.py.")

    else:
        print("Algo ha salido mal")



except (FileNotFoundError, IOError, FileExistsError, NotADirectoryError, KeyboardInterrupt, 
        AudioNotFoundError) as e:
    print(f"Error al abrir el archivo: {e}")
