# La profesora en apuros - Hackrocks

## Descripcion

Un conocido grupo de ransomware, **R7g6B54**, ha cifrado el ordenador de tu profesora. Sin embargo, parece que este grupo no es tan hábil como aparenta. Hace poco, intentaron atacar al equipo de un renombrado criptógrafo, pero este logró descifrar sus archivos y recuperar la clave en tan solo 15 minutos. El problema es que el criptógrafo, aunque mencionó su logro en su blog, no explicó los detalles técnicos de cómo lo logró. Ahora, todo lo que tienes para trabajar es:

- Una **Captura del mensaje de rescate** del grupo
- El nombre del grupo: **R7g6B54**

> ¿Serás capaz de encontrar la clave y liberar los archivos de tu profesora? ¡El tiempo corre!

## Solucion

![[Pasted image 20250824220258.png]]

> Archivos dados: `ransomware.png` y `Mensaje_con_flag.pdf.DBK`

Dentro de la descripcion hay una pista por donde podriamos iniciar la busqueda de la clave, **R7g6B54**, todas las imagenes poseen un plano *LSB* y un plano *RGB*, si prestamos atencion al nombre del grupo ransomware, este es un plano RGB, donde `R = 7`, `G = 6` y `B = 54`

Una herramienta que nos permite hacer busquedas en planos *LSB* y *RGB* es **Stegsolve**

![[Pasted image 20250824221832.png]]

Cuando previsualizamos la informacion dentro de ese plano de colores obtenemos una especie de codigo binario que al convertirlo a *plaintext* obtenemos un link

```
01101000 01110100 01110100 01110000 01110011 
00111010 00101111 00101111 01110011 01100101 
01100011 01100001 01100100 01101101 01101001 
01101110 00101110 01100101 01110011 00101111 
01110010 01100101 01110011 01100011 01110101 
01100101 00101110 01110100 01111000 01110100
```

- `https://secadmin.es/rescue.txt`

Conseguimos obtener un archivo txt, que probablemente poseea la flag en su interior, si navegamos a esta url en el navegador vemos lo siguiente: `Debemos siempre escribir el rescue en HTML, no txt`, en este caso sabemos que el **rescue** es el archivo al que accedimos, el *txt* no es valido, pero que pasa si seguimos la pista y le cambiamos la extension a *html*? 

![[Pasted image 20250824222715.png]]

Tenemos una clave, el otro archivo *DBK* no posee archivos embedidos asi que el desafio no consiste en extraer informacion de ese archivo, los `.dbk` son backups, asi que el archivo original conserva su extension la cual es `.pdf`, pero no es legible el pdf aunque le quitemos la extension de backup, por lo tanto si se habla de **ransomware**, podriamos deducir que el archivo pdf fue encriptado y la clave que recuperamos fue la usada para encryptarlo

- `41f4f4cfe129b4f353bb23ac5260846a`

Dado que solo tenemos la **key** y no el **iv**, podriamos usar el modo *CBC* de AES, pero dado que tenemos un archivo pdf, no podemos usar herramientas en linea, debemos crear un script en python

## Solution code

```
from Crypto.Cipher import AES

class Main:
	def main(self):
		key_ascii = b'41f4f4cfe129b4f353bb23ac5260846a'
		iv = b'\x00' * 16

		with open('Mensaje_con_flag.pdf.DBK', 'rb') as file:
			content = file.read()
		
		aes_decode = AES.new(key_ascii, AES.MODE_CBC, iv)
		decrypt = aes_decode.decrypt(content)
		
		with open('decode_flag.pdf', 'wb') as file:
			file.write(decrypt)

if __name__ == '__main__':
	Main().main()
```

Esto no genera un archivo pdf valido que si abrimos obtenemos la flag:

```
Documentos personales de la profe recuperados con éxito!!!!
Seguro que te va a poner un 10 en criptografía
Flag: SecAdmin{lateacher_feliz}
```

> La flag es: `SecAdmin{lateacher_feliz}`