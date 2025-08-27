# QR Code - N3XT_L3V3L

## Descripcion

Se le proporciona un código QR. Encuentra la bandera.

> Formato de bandera: n3xt{}
> Archivo dado: `image.jpg`

## Solucion

Tenemos un codigo **QR**

![[Pasted image 20250825190913.png]]

Una forma de encontrar la flag seria *parsear* el codigo, ya sea que nos de la flag en plaintext o encriptada o alguna url potencial para continuar con la resolucion, una herramienta que podemos usar es **cyberchef**: [Cyberchef](https://cyberchef.io/)

![[Pasted image 20250825191538.png]]

Es una *fake flag*, por lo que leyendo el codigo directamente no encontraremos la flag, podriamos intentar buscar informacion o archivos ocultos en la imagen, hay muchas herramientas, pero una bastante buena para extraer informacion y archivos ocultos es **stegseek**

- `stegseek image.jpg`

La siguiente informacion fue encontrada:

```
[i] Found passphrase: ""
[i] Original filename: "flag.dat".
[i] Extracting to "image.jpg.out".
```

Un nuevo archivo fue generado, a partir de un archivo llamado `flag.dat`que se encuentra en esta imagen, al leer el contenido: `P2JJRUxmOWBkMGBkMD9fZjBkXzBiY2RKTg==` podemos ver una cadena en **base64**

- `echo 'P2JJRUxmOWBkMGBkMD9fZjBkXzBiY2RKTg==' | base64 -d

El testo decodificado: ```?bIELf9`d0`d0?_f0d_0bcdJN``` no parece ser la flag, por lo que podriamos estar tratando con una especie de *encriptacion*, *codificacion* o *cifrado* previo a obtener la flag, tiene un aspecto poco comun, por lo que usaremos herramientas para detectar el tipo de cifrado: [Dcode Cipher Identifier](https://www.dcode.fr/cipher-identifier)

![[Pasted image 20250825192751.png]]

Tenemos dos posibles cifrados: *Rail Fence* y *ROT47*, el primero no nos da la flag, asi que ese no puede ser, pero si nuevamente usamos **cyberchef** para decodificar el *ciphertext* 

![[Pasted image 20250825193035.png]]

> La flag es: `n3xt{7h15_15_n07_50_345y}`

