# Malicious IP - N3XT_L3V3L
Se le proporciona un gran registro de acceso HTTP que contiene 75.000 entradas de un servicio API crítico. El registro incluye solicitudes de usuarios normales, bots ruidosos y un actor malicioso que realiza una secuencia de llamadas API sospechosas.

Su tarea es analizar el registro y encontrar la dirección IP responsable de la actividad maliciosa. El comportamiento del atacante sigue un patrón único e identificable de llamadas API integradas en los registros.

> Formato de bandera: `n3xt{malicious_ip}`
> Archivo dado: `critical_api_access.log`

## Solucion
Tenemos un archivolog y debemos encontrar la **IP**, en la descripcion podemos ver que de primeras nos estan diciendo que la ip maliciosa esa haciendo llamadas a la *API*. El archivo tiene el siguiente contenido

```
35.238.109.169 - - [11/Jul/2025:08:09:19 ] "GET /api/v1/items/search HTTP/1.1" 200 46233 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
45.146.165.23 - - [12/Jul/2025:13:56:07 ] "GET /p16gxxk6apdi HTTP/1.1" 404 312 "-" "Scrapy/2.5.0 (+https://scrapy.org)"
85.113.184.236 - - [23/Jul/2025:21:47:18 ] "GET /img/logo.svg HTTP/1.1" 200 24888 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
48.234.237.89 - - [12/Jul/2025:07:13:48 ] "GET /api/v1/items HTTP/1.1" 200 49699 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
```

Algunas *request* son basura, por lo que podriamos iniciar un descarte usando grep:

- `cat critical_api_access.log | grep '/api/v1/' | wc -l`

Pero esto no continua devolciendo mucha informacion, hay `35577` lineas que procesar, algo que podriamos hacer es eliminar duplicados usando como referencia la *API* 

```
cat critical_api_access.log | grep '/api/v1/' | awk -F '"' '{print $2}' | awk -F ' ' '{print $2}' | sort -u'
```

Lo cual nos muestra solamente `5` llamadas a la *API*

```
/api/v1/items
/api/v1/items/search
/api/v1/user/profile
/api/v1/user/settings
/api/v1/users/export?format=json&limit=1
```

Entre ellas `/api/v1/users/export?format=json&limit=1`, lo normal es que cuando hay un infiltracion, se produsca una **exfiltracion**, asi que si se esta exportando informacion puede estar sucediendo una exfiltracion, por ende este es el actor malisioso

```
172.105.99.15 - - [17/Jul/2025:00:28:33 ] "GET /api/v1/users/export?format=json&limit=1 HTTP/1.1" 200 5242880 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
```

> La flag es: `n3xt{172.105.99.15}

