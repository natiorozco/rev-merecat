# Análisis de seguridad — `libhttpd.c` (líneas 1-2000)

**Archivo analizado:** `src/libhttpd.c` (limitado a las primeras 2000 líneas, por alcance solicitado)
**Herramienta:** Revisión manual asistida por Claude (Sonnet 5)
**Fecha:** 2026-09-04

`libhttpd.c` es el núcleo del servidor HTTP **merecat** (fork de thttpd). El rango revisado cubre inicialización del servidor, envío de cabeceras/errores (`send_mime`, `send_response`), control de acceso por directorio (`.htaccess`/`.htpasswd`), redirecciones HTTP y mapeo de virtual hosts / tildes. Se identificaron las siguientes debilidades, ordenadas de mayor a menor gravedad. Dos hallazgos (#1 y #4) están confirmados de forma remota y no autenticada.

---

## 🔴 Gravedad Alta

### 1. Datos de cliente (`Host`, URI, query string) inyectados como variables de entorno y expandidos con `wordexp()`
- **Ubicación:** `libhttpd.c:1564-1626` (`send_redirect`), específicamente `setenv()` en las líneas 1594, 1599, 1605, 1607 y la llamada a `wordexp()` en la línea 1609.
- **CWE:** CWE-88 (Argument Injection / Improper Neutralization of Argument Delimiters), con impacto demostrable de CWE-200 (Information Exposure)
- **Explotable:** Sí, de forma remota y no autenticada — **y es exactamente el patrón de configuración que el propio proyecto documenta como uso recomendado** (ver `README.md:173-175` y `merecat.conf:127-129`: `location = "https://$host$request_uri$args"`, el ejemplo oficial para redirigir HTTP → HTTPS).
- **Descripción:** El código toma directamente el header `Host` (`hc->hdrhost`), la URL solicitada (`hc->encodedurl`) y la query string, y los expone como variables de entorno del proceso (`host`, `request_uri`, `args`) sin ningún saneamiento. Acto seguido llama a `wordexp(redirect->location, &we, 0)` — expansión de palabras al estilo shell POSIX — sobre la plantilla de redirección configurada por el administrador, que en el uso documentado referencia justamente esas tres variables sin comillas.
  Aunque el **valor sustituido de una variable no se re-evalúa como comando** (por lo que no hay inyección de `$(...)`/backticks trivial vía cabeceras), `wordexp()` sí aplica sobre el resultado de la sustitución, sin comillas:
  - **División de palabras (IFS)**: si el `Host` o la URI contienen espacios/tabs, `we.we_wordv[0]` (la única palabra usada) queda truncada/alterada de forma no controlada por el administrador, pudiendo desviar el destino real del redirect.
  - **Expansión de nombre de ruta (globbing)**: si el atacante incluye `*`, `?` o `[...]` en el `Host` (p. ej. `Host: *`) o en la URI, `wordexp()` los expande contra el **directorio de trabajo del proceso httpd**, y el/los nombre(s) de archivo resultantes se reflejan de vuelta al cliente en la cabecera `Location:` y en el cuerpo de la respuesta de error/redirect (`send_response(hc, ..., we.we_wordv[0])`), filtrando así nombres de archivos del sistema de archivos del servidor.
  - Adicionalmente, si en algún momento la propia plantilla del administrador (`redirect->location`) llega a incorporar `$(...)` o backticks (p. ej. por error de configuración o generación dinámica de dicha plantilla), `wordexp()` sí ejecuta sustitución de comandos real, ya que se invoca con flags `0` (sin `WRDE_NOCMD`).
- **Corrección recomendada:** nunca usar `wordexp()` sobre datos derivados de la red. Sustituir por una plantilla propia con `snprintf`/reemplazo de tokens literal (`$host`, `$request_uri`, `$args`) sin pasar por un intérprete de shell, o como mínimo invocar `wordexp()` con la flag `WRDE_NOCMD` (que sigue sin evitar el globbing/word-splitting, por lo que no es suficiente por sí sola).

---

## 🟠 Gravedad Media

### 2. Lectura fuera de límites por subdesbordamiento de entero en `find_htfile()`
- **Ubicación:** `libhttpd.c:1117-1164`, en particular `dirlen = strlen(dir)` (línea 1121) y su uso en `dir[dirlen - 1]` (línea 1128).
- **CWE:** CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **Explotable:** Condicional — requiere que el `dir` recibido sea una cadena vacía (p. ej. combinaciones de vhost con nombre de host vacío, mapeo de tilde, u otras rutas construidas más adelante en el archivo que dejen `hc->expnfilename` comenzando por `/`). El defecto de programación en sí (subdesbordamiento sin signo) es cierto independientemente de qué tan fácil sea alcanzarlo con una petición típica.
- **Descripción:** Si `dir` es `""`, `dirlen` vale `0` y `dirlen - 1` **subdesborda** (tipo `size_t`, sin signo) a `SIZE_MAX`. La expresión `dir[dirlen - 1]` intenta entonces leer en un desplazamiento absurdamente grande respecto a `dir`, lo que constituye un acceso fuera de límites y muy probablemente provoca un fallo de segmentación (DoS del proceso trabajador) al procesar la petición. Nótese que la línea ya contempla el caso `dir` vacío para la parte `%s` del `snprintf` (`dir[0] ? dir : "."`), pero **no** aplica esa misma sustitución antes de calcular `dirlen - 1`, por lo que la protección es incompleta.

### 3. Lectura fuera de límites al procesar una línea que empieza con un byte NUL en `.htaccess`/`.htpasswd`
- **Ubicación:** `libhttpd.c:1263-1266` (`access_check2`) y `libhttpd.c:1507-1511` (`auth_check2`)
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Explotable:** Requiere poder introducir un byte `\0` como primer carácter de una línea del archivo de control de acceso o de contraseñas (por ejemplo, en despliegues de hosting compartido donde el propio usuario gestiona su `.htaccess`/`.htpasswd`, o si el servidor permite subir/escribir archivos en el árbol servido).
- **Descripción:** El patrón `l = strlen(line); if (line[l - 1] == '\n') ...` asume `l >= 1`. Si la línea leída por `fgets()` comienza con un byte NUL literal, `strlen(line)` devuelve `0`, y `line[l - 1]` se convierte en `line[-1]` — una lectura un byte antes del inicio del buffer de pila `line[500]`.

### 4. Lectura fuera de límites en la tabla de decodificación Base64 por indexación con `char` con signo
- **Ubicación:** `src/base64.c:48` (`d = b64_decode_table[(int)*cp];`), alcanzable de forma remota y **no autenticada** desde `libhttpd.c:1457` (`auth_check2`, `l = b64_decode(&(hc->authorization[6]), ...)`)
- **CWE:** CWE-129 (Improper Validation of Array Index) → CWE-125 (Out-of-bounds Read)
- **Explotable:** Sí, de forma trivial y remota. `*cp` es un `char` (con signo por defecto en la mayoría de plataformas x86/ARM con gcc); si el byte decodificado tiene el bit alto activo (`0x80`-`0xFF`), `(int)*cp` se extiende con signo a un valor **negativo** (p. ej. `0x80` → `-128`), y `b64_decode_table[-128]` lee memoria estática **anterior** a la tabla `b64_decode_table[256]`.
- **Descripción:** Un atacante que envíe una cabecera `Authorization: Basic <byte-alto>...` hacia cualquier directorio protegido por `.htpasswd` (habilitado por defecto: `AUTH_FILE ".htpasswd"`) dispara esta lectura fuera de límites sin necesidad de autenticarse. El impacto práctico es limitado (el valor leído solo influye en el byte decodificado internamente, no se refleja directamente al cliente), pero es un defecto de memoria real y determinista, de corrección trivial (castear a `unsigned char` antes de indexar).

### 5. Condición de carrera (TOCTOU) entre la comprobación de existencia y la apertura de `.htaccess`/`.htpasswd`
- **Ubicación:** `libhttpd.c:1243-1249` (`access_check2`: `lstat` → `fopen`) y `libhttpd.c:1441-1494` (`auth_check2`: `lstat` → `stat` → `fopen`)
- **CWE:** CWE-367 (Time-of-check Time-of-use)
- **Explotable:** Requiere un atacante local con capacidad de escritura en el árbol de directorios servido (escenario típico de hosting compartido, que es precisamente el modelo de despliegue para el que existen estas comprobaciones de `.htaccess`/`.htpasswd`).
- **Descripción:** Entre la comprobación de que el archivo existe (`lstat`/`stat`) y su apertura real (`fopen`), un atacante local podría sustituir el archivo (p. ej. por un symlink a un archivo con permisos distintos) para alterar el resultado de la comprobación de control de acceso.

---

## 🟡 Gravedad Baja

### 6. Parámetro `type` usado directamente como cadena de formato en `snprintf`
- **Ubicación:** `libhttpd.c:792` (`snprintf(fixed_type, sizeof(fixed_type), type, hc->hs->charset);`, dentro de `send_mime`)
- **CWE:** CWE-134 (Uncontrolled Format String)
- **Explotable:** No con los puntos de llamada vistos en este rango (todos pasan literales fijos como `"text/html; charset=%s"`), pero es un patrón frágil: si algún tipo MIME proveniente de una tabla/config (`figure_mime()`, no incluido en este rango) llegase a contener un `%` inesperado, `snprintf` leería un argumento variádico inexistente.

### 7. Arreglo de longitud variable (VLA) dimensionado con datos del cliente sin límite local
- **Ubicación:** `libhttpd.c:1602` (`char query[strlen(ptr) + 2];`, dentro de `send_redirect`)
- **CWE:** CWE-1284 / CWE-789 (dimensionamiento de memoria con cantidad no verificada)
- **Explotable:** Depende de si existe un límite superior efectivo para la longitud de la URL en otra parte del código (fuera del rango de 2000 líneas revisado). Si no lo hay, una URL muy larga podría agotar la pila del proceso.

### 8. Comparación de contraseñas cifradas sin tiempo constante
- **Ubicación:** `libhttpd.c:1481` y `libhttpd.c:1529` (`strcmp(crypt_result, ...)` en `auth_check2`)
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Explotable:** Teórico/bajo impacto — el coste de `crypt()` domina el tiempo total de la comparación, por lo que el canal de temporización que aportaría `strcmp` es marginal frente al ruido de red. Se menciona como buena práctica de refuerzo (usar una comparación de tiempo constante), no como vulnerabilidad crítica.

---

## ℹ️ Informativo

- **Posible desbordamiento de entero en el cálculo de crecimiento de `httpd_realloc_str()`** (`libhttpd.c:919`, `*curr_len = MAX(*curr_len * 2, new_len * 5 / 4);`): con un `new_len` cercano a `SIZE_MAX` la multiplicación podría desbordar, resultando en una reserva de memoria menor a la necesaria (CWE-190). En la práctica, los tamaños que se acumulan en este archivo (cabeceras HTTP, rutas) están muy lejos de ese rango en una arquitectura de 64 bits, por lo que el riesgo es puramente teórico.

---

## Resumen

| # | Debilidad | CWE | Gravedad | Explotable |
|---|---|---|---|---|
| 1 | `setenv()`+`wordexp()` con datos de cliente en `send_redirect()` | CWE-88/200 | Alta | Sí (remoto, patrón documentado oficialmente) |
| 2 | Subdesbordamiento de entero en `find_htfile()` | CWE-191/125 | Media | Condicional |
| 3 | Lectura OOB con línea que inicia en NUL (`access_check2`/`auth_check2`) | CWE-125 | Media | Condicional (hosting compartido) |
| 4 | Indexación con `char` con signo en `b64_decode_table` | CWE-129/125 | Media | Sí (remoto, no autenticado) |
| 5 | TOCTOU en lectura de `.htaccess`/`.htpasswd` | CWE-367 | Media | Local (hosting compartido) |
| 6 | `type` como cadena de formato en `send_mime` | CWE-134 | Baja | No, con los call sites actuales |
| 7 | VLA dimensionado por datos de cliente | CWE-1284/789 | Baja | Depende de límites externos |
| 8 | Comparación de contraseñas sin tiempo constante | CWE-208 | Baja | Teórico |

### Prioridad de corrección

El hallazgo **#1** es el más importante: no solo es alcanzable de forma remota y no autenticada, sino que corresponde **exactamente al ejemplo de configuración que el propio `README.md` recomienda** para el caso de uso más común (redirigir HTTP a HTTPS), por lo que cualquier despliegue que siga la documentación oficial queda expuesto a filtración de nombres de archivo del servidor vía manipulación del header `Host` o de la URL. El hallazgo **#4** es el segundo más urgente por ser trivial de disparar (una sola cabecera `Authorization` con un byte alto) aunque su impacto práctico sea menor. Los hallazgos **#2, #3 y #5** son defectos reales de memoria/concurrencia cuya explotación depende de condiciones de despliegue específicas (vhosts, hosting compartido), pero deberían corregirse igualmente por robustez.
