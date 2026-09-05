# Análisis de seguridad — `htpasswd.c`

**Archivo analizado:** `src/htpasswd.c`
**Herramienta:** Revisión manual asistida por Claude (Sonnet 5)
**Fecha:** 2026-09-04

Es la típica utilidad NCSA/Apache `htpasswd` adaptada para uso en CGI (ver comentario de cabecera en `htpasswd.c:7-9`). Se identificaron las siguientes debilidades, ordenadas de mayor a menor gravedad.

---

## 🔴 Gravedad Alta

### 1. Desbordamiento de buffer por off-by-one en `get_password()`
- **Ubicación:** `htpasswd.c:106-113`
- **CWE:** CWE-193 (Off-by-one Error) → CWE-787 (Out-of-bounds Write)
- **Explotable:** Sí, de forma local/interactiva.
- **Descripción:** La condición de salida `pos < len` se evalúa **después** de escribir `password[pos++]`. Con `len=100` (`pass[100]` en `htpasswd.c:123`), si el usuario teclea ≥100 caracteres sin Enter, `pos` llega a 100 y luego se ejecuta `password[100] = 0` — un byte fuera de los límites del arreglo de la pila. Escritura de 1 byte NUL fuera de límites en la pila de `add_password()`. Dependiendo del layout de variables del compilador puede corromper `pw`, `cpw`, `salt` o el relleno adyacente. Requiere entrada interactiva local (no explotable remotamente vía el modo CGI/stdin, que usa `fgets` correctamente acotado).

### 2. Uso de PRNG criptográficamente débil para generar el "salt"
- **Ubicación:** `htpasswd.c:169-170`
- **CWE:** CWE-338 (Use of Cryptographically Weak PRNG)
- **Explotable:** Sí.
- **Descripción:** `srandom(time(NULL))` se re-siembra en **cada** llamada a `add_password()` con la hora actual (resolución de 1 segundo). Si se crean/cambian varias cuentas en el mismo segundo (scripts, procesos por lotes), se generan **salts idénticos**. Además, el salt es predecible conociendo aproximadamente el momento de creación, lo que reduce el espacio de búsqueda para ataques offline / rainbow tables.

---

## 🟠 Gravedad Media

### 3. Algoritmo de hash de contraseña débil/obsoleto
- **Ubicación:** `htpasswd.c:126-136`, `htpasswd.c:172`
- **CWE:** CWE-916 (Insufficient Computational Effort)
- **Explotable:** Sí, si el archivo htpasswd se filtra.
- **Descripción:** Usa MD5-crypt (`$1$`) o, si el sistema no lo soporta, cae a **DES crypt clásico** (trunca la contraseña a 8 caracteres útiles). Ambos son crackeables a alta velocidad con GPU frente a bcrypt/scrypt/Argon2.

### 4. Condición de carrera al modificar el archivo compartido de contraseñas
- **Ubicación:** `htpasswd.c:292-362`
- **CWE:** CWE-362 / CWE-367 (Race Condition / TOCTOU)
- **Explotable:** Sí, en el escenario que el propio código dice soportar (CGI, es decir, múltiples invocaciones concurrentes del binario).
- **Descripción:** No hay `flock()`/`lockf()` sobre el archivo real. Dos procesos concurrentes leen el mismo archivo original, escriben cada uno su temporal y luego sobrescriben el destino → el último en terminar gana y **descarta silenciosamente** el cambio del otro (p. ej. un cambio de contraseña legítimo puede perderse).

### 5. Reemplazo no atómico del archivo de contraseñas
- **Ubicación:** `htpasswd.c:179-209`
- **CWE:** CWE-362 (falta de atomicidad en actualización de recurso crítico)
- **Explotable:** Parcialmente (requiere que el proceso muera a mitad de camino: kill, disco lleno, falta de energía).
- **Descripción:** `fopen(file, "w")` trunca el archivo destino **antes** de copiar el contenido nuevo. Si el proceso se interrumpe entre el truncado y el `fclose`, el archivo de contraseñas queda vacío o truncado → DoS de autenticación (todos los usuarios bloqueados, o pérdida de entradas).

### 6. Permisos por defecto inseguros en el archivo de contraseñas
- **Ubicación:** `htpasswd.c:252`, `htpasswd.c:188`
- **CWE:** CWE-276 / CWE-732 (Incorrect Default Permissions)
- **Explotable:** Sí, en sistemas multiusuario.
- **Descripción:** `fopen(..., "w")` crea el archivo con los permisos por defecto del `umask` del proceso (típicamente 0644), sin `chmod` explícito a algo restrictivo (0600). El archivo contiene hashes de contraseñas: si el umask es laxo, queda legible por otros usuarios locales, habilitando cracking offline.

### 7. Pérdida silenciosa de la última entrada si el archivo no termina en salto de línea
- **Ubicación:** `htpasswd.c:50-66`, `htpasswd.c:334`
- **CWE:** CWE-704 (Incorrect Type Conversion, causa raíz) → pérdida de integridad de datos
- **Explotable:** Sí, de forma reproducible.
- **Descripción:** `get_line()` castea el valor de `fgetc()` (que puede ser `EOF` = -1) a `char` **antes** de compararlo, así que EOF nunca coincide con `LF`/`0x4` y el bucle sigue escribiendo bytes basura hasta `n-1`. Como el `while (!get_line(...))` en `htpasswd.c:334` es de pre-condición, esa última línea "corrupta" detectada como EOF **nunca se escribe** al archivo de salida. Resultado práctico: si el htpasswd no termina con `\n`, al modificar/agregar cualquier usuario, **el último usuario del archivo desaparece sin ningún aviso o error**.

---

## 🟡 Gravedad Baja

### 8. Validación de nombre de archivo aplicada después del efecto (orden incorrecto)
- **Ubicación:** `htpasswd.c:248-269`
- **CWE:** CWE-696 (Incorrect Behavior Order)
- **Explotable:** Limitado (requiere que un wrapper externo pase `argv[2]` con `;`/`>` sin pasar por shell).
- **Descripción:** `fopen(argv[2], "w")` en `htpasswd.c:252` ya trunca/crea el archivo **antes** de validar longitud o caracteres ilegales (`htpasswd.c:259-269`). Si la validación falla después, el archivo ya fue destruido/truncado pese a que la operación se "rechaza".

### 9. Lista negra de caracteres incompleta en nombres de archivo
- **Ubicación:** `htpasswd.c:265-266`, `htpasswd.c:306-310`
- **CWE:** CWE-184 (Incomplete Blacklist)
- **Explotable:** No directamente en este archivo (no invoca shell), pero da falsa sensación de seguridad si algún wrapper externo pasa el nombre de archivo a `system()`/`popen()`.
- **Descripción:** Solo bloquea `;` y `>`; deja pasar `|`, `&`, backticks, `$()`, saltos de línea, etc.

### 10. Uso de funciones no seguras para señales dentro del manejador de `SIGINT`
- **Ubicación:** `htpasswd.c:219-229`
- **CWE:** CWE-479 (Signal Handler Use of a Non-reentrant Function) / CWE-364
- **Explotable:** Bajo/teórico.
- **Descripción:** `interrupted()` llama a `fprintf`, `tcsetattr`, `unlink` y `exit`, ninguna async-signal-safe. Un `Ctrl+C` durante una llamada a stdio en curso puede dejar buffers de `stdio` inconsistentes (crash o comportamiento indefinido), más un problema de robustez que de RCE práctico.

### 11. Sin política de complejidad/longitud mínima de contraseña
- **Ubicación:** `htpasswd.c:106-119`, `htpasswd.c:138-146`
- **CWE:** CWE-521 (Weak Password Requirements)
- **Explotable:** Trivialmente (Enter vacío = contraseña vacía aceptada), pero es una brecha de política, no una vulnerabilidad de memoria.

---

## ℹ️ Informativo

- **Patrón frágil de copia entre buffers de tamaño fijo** en `getword()` / `strcpy(l, line)` (`htpasswd.c:340-341`): hoy es seguro porque `line`, `l` y `w` comparten `MAX_STRING_LEN`, pero `getword()` no valida tamaños internamente — cualquier refactor que desincronice esos tamaños introduciría un desbordamiento clásico (CWE-120).
- **Fuga de memoria menor**: el `strdup(pw)` en `htpasswd.c:158` nunca se libera (CWE-401), irrelevante dado el ciclo de vida corto del proceso.

---

## Resumen

| # | Debilidad | CWE | Gravedad | Explotable |
|---|---|---|---|---|
| 1 | Off-by-one en `get_password()` | CWE-193/787 | Alta | Sí (local) |
| 2 | Salt con PRNG predecible | CWE-338 | Alta | Sí |
| 3 | Hash MD5/DES-crypt débil | CWE-916 | Media | Sí (offline) |
| 4 | Race condition sin locking | CWE-362/367 | Media | Sí (CGI concurrente) |
| 5 | Reemplazo no atómico del archivo | CWE-362 | Media | Parcial |
| 6 | Permisos por defecto laxos | CWE-276/732 | Media | Sí (multiusuario) |
| 7 | Pérdida silenciosa de última línea | CWE-704 | Media | Sí (reproducible) |
| 8 | Validación tras truncar archivo | CWE-696 | Baja | Limitado |
| 9 | Lista negra incompleta | CWE-184 | Baja | Indirecto |
| 10 | Signal handler inseguro | CWE-479 | Baja | Teórico |
| 11 | Sin política de contraseñas | CWE-521 | Baja | Trivial |

### Prioridad de corrección

Los hallazgos **#1, #2 y #7** son los más "reales" a resolver primero: el off-by-one es un bug de memoria concreto y demostrable, el PRNG débil compromete directamente la propiedad de seguridad que el salt busca dar, y la pérdida silenciosa de la última línea es un bug de integridad fácil de reproducir con impacto directo en control de acceso (borra credenciales sin avisar).
