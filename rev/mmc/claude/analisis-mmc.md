# Análisis de seguridad — `mmc.c`

**Archivo analizado:** `src/mmc.c` (616 líneas, completo)
**Herramienta:** Revisión manual asistida por Claude (Sonnet 5)
**Fecha:** 2026-09-04

`mmc.c` implementa la caché de archivos mapeados en memoria (`mmap`) del servidor **merecat**, incluyendo el soporte de iconos embebidos (`BUILTIN_ICONS`). Para verificar los hallazgos se cruzó este archivo con sus puntos de llamada reales en `src/libhttpd.c` (`mmc_icon_check` en la línea 4597 y `mmc_map` en la línea 4842). Se identificaron las siguientes debilidades, ordenadas de mayor a menor gravedad.

---

## 🟠 Gravedad Media

### 1. Variable local desconectada en el fallback de iconos embebidos (`mmc_map` / `mmc_icon_open`)
- **Ubicación:** `mmc.c:215-260` (`mmc_map`), en particular la llamada `mmc_icon_open(filename, &buf, &sb)` en la línea 256, y `mmc.c:189-203` (`mmc_icon_open`, línea 200: `*st = icost;`)
- **CWE:** CWE-664 (Improper Control of a Resource Through its Lifetime, causa raíz) → CWE-125 (Out-of-bounds Read) → CWE-200 (Information Exposure)
- **Explotable:** **No con el código actual** (ver más abajo), pero es un defecto latente de mantenibilidad que un cambio aparentemente inocuo convertiría en una fuga de memoria del servidor hacia el cliente HTTP.
- **Descripción:** Cuando `open(filename, O_RDONLY)` falla (línea 254) — el caso normal para los iconos embebidos, que no existen como archivos reales — se invoca `mmc_icon_open(filename, &buf, &sb)`, que escribe el `struct stat` sintético del icono (`icost`, con el tamaño **real** decodificado del icono) en la variable **local** `sb` de `mmc_map`. Sin embargo, el tamaño que realmente se usa más abajo para reservar memoria y copiar datos es el del parámetro **`st`** de la función (`m->size = st->st_size;`, línea 282; `size_t len = (size_t)m->size;`, línea 294; `memcpy(m->addr, buf, len);`, línea 305) — y `st` **solo** es igual a `&sb` si el llamador invocó `mmc_map()` con `st == NULL`.
  El único punto de llamada actual (`libhttpd.c:4842`, `mmc_map(hc->expnfilename, &(hc->sb), now)`) siempre pasa un puntero no nulo (`&hc->sb`), y "por casualidad" funciona correctamente porque el propio `libhttpd.c` llama antes a `mmc_icon_check(hc->decodedurl, &hc->sb)` (línea 4597), que ya deja `hc->sb.st_size` con el tamaño correcto del icono. Es decir, **el código de `mmc.c` no es autocontenido**: su corrección depende de un invariante mantenido en otro archivo. Si en el futuro `mmc_map()` se invoca para una ruta de icono sin ese pre-poblado (una llamada directa con `st` apuntando a un `struct stat` de un archivo real que no existe, o un refactor que reordene las llamadas), `st->st_size` podría contener un valor arbitrario/mayor a 512, y `memcpy(m->addr, buf, len)` leería **más allá del búfer fijo `icon[512]`** (línea 153), copiando memoria adyacente del proceso hacia una respuesta HTTP servida al cliente.
- **Corrección recomendada:** que `mmc_icon_open()` reciba y actualice el mismo `st` que usará el resto de `mmc_map()` (es decir, pasar `st` en vez de `&sb` en la línea 256), eliminando la dependencia implícita entre archivos.

### 2. `free()` sobre una dirección de `mmap()` cuando el inodo es `0`
- **Ubicación:** `mmc.c:448-459` (`really_unmap`)
- **CWE:** CWE-590 (Free of Memory Not on the Heap) / CWE-704 (colisión de valor centinela)
- **Explotable:** Bajo — depende de que el sistema de archivos subyacente reporte `st_ino == 0` para un archivo real (poco común en `ext4`/`xfs`/`btrfs`, pero documentado en algunos sistemas de archivos virtuales/red o configuraciones inusuales).
- **Descripción:** El código usa `m->ino == 0` como marca para distinguir "icono embebido" (reservado con `malloc`, se libera con `free`) de "archivo real" (mapeado con `mmap`, se libera con `munmap`):
  ```c
  if (!m->ino)
      free(m->addr);
  else if (-1 == munmap(m->addr, m->size))
      ...
  ```
  Si un archivo real llega a tener `st_ino == 0`, `really_unmap()` llamaría a `free()` sobre una dirección devuelta por `mmap()`, lo cual es comportamiento indefinido y puede corromper el heap o abortar el proceso.

### 3. Identidad de caché basada en metadatos (inodo, dispositivo, tamaño, ctime) en vez de contenido
- **Ubicación:** `mmc.c:566-586` (`find_hash`), usado en `mmc.c:244` y `mmc.c:331`
- **CWE:** CWE-367 (Time-of-check Time-of-use) / CWE-354 (Improper Validation of Integrity Check Value)
- **Explotable:** Requiere un atacante local con capacidad de escritura en el árbol servido (modelo de hosting compartido, coherente con hallazgos similares ya reportados para `libhttpd.c`).
- **Descripción:** La caché considera dos archivos "el mismo" si coinciden `(ino, dev, size, ctime)`. Si un atacante local sustituye un archivo por otro de igual tamaño dentro del mismo segundo de `ctime` (o si el sistema de archivos reutiliza un número de inodo), el servidor podría seguir sirviendo desde la caché el contenido **antiguo** (o, según el orden de las operaciones, servir contenido de un archivo distinto) hasta que expire la entrada, sin detectar el cambio real del archivo en disco.

### 4. Truncamiento de `off_t` a `size_t` para archivos grandes (reconocido por el propio código)
- **Ubicación:** `mmc.c:294` (`size_t len = (size_t)m->size; /* loses on files >2GB */`)
- **CWE:** CWE-190 (Integer Overflow/Truncation) → CWE-681 (Incorrect Conversion between Numeric Types) → CWE-125 (Out-of-bounds Read) como consecuencia
- **Explotable:** Solo en compilaciones donde `size_t` es de 32 bits (arquitecturas/objetivos de 32 bits) y se sirven archivos mayores a ~4 GiB (el propio comentario ya admite el problema desde 2 GiB en plataformas donde `off_t` de 32 bits sin `_FILE_OFFSET_BITS=64` esté en juego).
- **Descripción:** `m->size` (tipo `off_t`, potencialmente de 64 bits) se trunca a `len` (`size_t`, de 32 bits en esas plataformas) antes de pasarlo a `malloc()`/`mmap()`. El mapeo resultante sería más pequeño que el valor real de `m->size`, que sigue siendo el que el resto del servidor usa (p. ej. para `Content-Length`). El resultado es una discrepancia entre el tamaño realmente mapeado y el tamaño que el servidor cree tener disponible, lo que puede derivar en una lectura fuera de límites del mapeo al intentar servir el archivo completo.

---

## 🟡 Gravedad Baja

### 5. Apertura bloqueante del archivo sin verificar que sea un archivo regular
- **Ubicación:** `mmc.c:254` (`fd = open(filename, O_RDONLY);`)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Explotable:** Requiere que un atacante local pueda colocar un archivo especial (p. ej. un FIFO) en el árbol servido; de nuevo, un escenario de hosting compartido o de directorios con permisos de escritura para usuarios no confiables.
- **Descripción:** `mmc.c` no comprueba por sí mismo que la ruta corresponda a un archivo regular antes de abrirla. Si el llamador (`libhttpd.c`, fuera de este archivo) no filtra el tipo de archivo, abrir un FIFO sin datos pendientes bloquearía indefinidamente el proceso/hilo que atiende la petición, agotando los recursos del servidor con solicitudes concurrentes.

---

## ℹ️ Informativo

- **Constante mágica de timestamp sin documentar:** `icost.st_ctim.tv_sec = 18446744073359756536UL;` (`mmc.c:177`) asigna un valor cercano a `2^64` al tiempo de creación sintético de los iconos embebidos. No es un problema de seguridad en sí, pero al interpretarse como `time_t` con signo produce una fecha absurda (miles de millones de años en el pasado); conviene documentar la intención (¿evitar colisiones de caché con archivos reales?) o reemplazarla por una constante con nombre.

---

## Resumen

| # | Debilidad | CWE | Gravedad | Explotable |
|---|---|---|---|---|
| 1 | `st` vs `sb` desconectados en fallback de iconos (`mmc_map`/`mmc_icon_open`) | CWE-664/125/200 | Media | No con el código actual (latente) |
| 2 | `free()` sobre dirección de `mmap()` si `ino == 0` | CWE-590 | Media | Bajo (depende del filesystem) |
| 3 | Identidad de caché por metadatos, no por contenido | CWE-367/354 | Media | Local (hosting compartido) |
| 4 | Truncamiento `off_t`→`size_t` en archivos grandes | CWE-190/681/125 | Media | Solo en builds de 32 bits |
| 5 | `open()` bloqueante sin verificar tipo de archivo | CWE-400 | Baja | Local (hosting compartido) |

### Prioridad de corrección

El hallazgo **#1** es el más interesante desde el punto de vista de diseño: hoy no es explotable porque `libhttpd.c` mantiene manualmente el invariante que `mmc.c` necesita, pero es exactamente el tipo de acoplamiento implícito entre archivos que suele romperse en un refactor futuro y convertirse en una fuga de memoria del servidor. Los hallazgos **#2 y #4** son defectos de manejo de tipos/memoria con bajo riesgo práctico en despliegues típicos (Linux 64 bits con sistemas de archivos convencionales), pero deberían corregirse por robustez. El hallazgo **#3** es compartido conceptualmente con el diseño de control de acceso ya señalado en el análisis de `libhttpd.c` (mismo modelo de amenaza: hosting compartido con usuarios no confiables escribiendo en el árbol servido).
