# History

## Descripcion

En lo más profundo de la base de datos del historial del navegador se esconde un secreto. Sólo aquellos que examinen cuidadosamente las marcas de tiempo, las URL y las entradas ocultas descubrirán la bandera. Profundiza: la respuesta espera a los persistentes

> Archivo dado: `history.db`

## Solucion

Lo mas importante es determinar el tipo de **base de datos**: `file history.sb`, esto nos dira que tipo de base de datos es para asi proceder con el analisis

```
history.db: SQLite 3.x database...
```

Para las bases de datos *SQLite3* existe una herramienta muy cool para evitar usar la terminal, se llama **SQLite Browser**, la cual podemos instalar en kali o descargar el `.AppImage`

- `sudo apt install sqlitebrowser`
- [Download SQLite Browser](https://sqlitebrowser.org/dl/)

![[Pasted image 20250825125757.png]]

En la base de datos existen muchas url que usan parametros para llamar o acceder a algo, la informacion que se le pasa a esos parametros parece estar en **base64**, el formato de las flags para este CTF es `n3xt{}` por lo que podriamos crear un filtro para que nos muestra solo la informacion que podria ser la flag, `n3xt{` en base64 es: `bjN4`

![[Pasted image 20250825131244.png]]

El mismo filtro se puede aplicar usando una *query*:

```
SELECT * FROM urls WHERE url LIKE '%bjN4%'
```

Dado que es **base64** con un simple `echo` podemos decodificarlo:

- `echo 'bjN4dHtkNHQ0XzBjMzRuX2QxdjNyX200c3Qzcn0=' | base64 -d`

> La flag es: `n3xt{d4t4_0c34n_d1v3r_m4st3r}`
