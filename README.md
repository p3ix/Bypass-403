# Bypass Tool (403 Bypass Toolkit)

Herramienta CLI en Python para pruebas de bypass de controles de acceso (403/40X) en entornos autorizados de DevSec y Bug Bounty.

Incluye pruebas de:

- mutaciones de ruta
- cabeceras de proxy/IP
- verbos y method override
- query/pollution
- protocolos (`HTTP/1.0`, `HTTP/1.1`, `HTTP/2`)
- fuzzing Host/SNI/authority
- checks de smuggling-lite diferenciales

## Aviso legal

Usa esta herramienta solo contra activos donde tengas permiso explícito.  
No la uses fuera de alcance o contra terceros sin autorización.

## Requisitos

- Python `>= 3.10`
- Linux/macOS/WSL recomendado

## Instalación

```bash
cd ~/Bypass
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Comprobar ayuda:

```bash
python -m bypass --help
python -m bypass probe --help
```

## Comandos principales

- `probe`: lanza pruebas contra un target
- `batch`: ejecuta sobre lista de URLs
- `replay`: reintenta hallazgos exportados
- `list`: muestra tamaño de catálogos cargados

## Modos de escaneo (`--mode`)

- `path`: mutaciones de ruta
- `headers`: payloads de cabeceras
- `both`: path + headers + query
- `methods`: verb tampering y overrides
- `query`: mutaciones de query
- `protocol`: `HTTP/1.0`, `HTTP/1.1`, `HTTP/2`
- `host`: fuzzing Host/SNI/authority
- `smuggling`: probes smuggling-lite
- `all`: ejecuta todo en una pasada (sin deduplicar)

## Flags más importantes

- `--profile safe|aggressive`: intensidad del motor
- `--combine`: combina path+headers (costoso)
- `--guided-combos`: combinaciones guiadas de técnicas
- `--host-fuzz`: activa fuzzing extendido Host/SNI
- `--host-fuzz-value <host>`: valor extra host/authority (repetible)
- `--smuggling-lite`: activa probes smuggling-lite
- `--smuggling-limit N`: máximo probes smuggling por target
- `--bypass-ip <ip>`: IP/host extra para payloads tipo XFF (repetible)
- `--calibrate --calibration-samples N`: calibración dinámica baseline
- `--all`: mostrar todas las filas (no solo interesantes)
- `-k`: desactivar validación TLS (cert autofirmado/lab)
- `-L`: seguir redirecciones
- `--json out.json` / `--csv out.csv`: exportes

## Uso rápido

### 1) Escaneo base

```bash
python -m bypass probe "https://target.tld/admin" --mode both
```

### 2) Target con TLS autofirmado

```bash
python -m bypass probe "https://192.168.0.18:8443/host-manager/" --mode both -k
```

### 3) Solo protocolos

```bash
python -m bypass probe "https://target.tld/admin" --mode protocol -k --all
```

### 4) Solo Host/SNI fuzzing

```bash
python -m bypass probe "https://target.tld/admin" \
  --mode host \
  --host-fuzz \
  --host-fuzz-value internal.target.tld \
  --host-fuzz-value localhost \
  -k --all
```

### 5) Solo smuggling-lite

```bash
python -m bypass probe "https://target.tld/admin" \
  --mode smuggling \
  --smuggling-lite \
  --smuggling-limit 30 \
  -k --all
```

## Comando FULL agresivo (todo)

```bash
python -m bypass probe "https://target.tld/admin" \
  --mode all \
  --profile aggressive \
  --combine \
  --guided-combos \
  --host-fuzz \
  --host-fuzz-value localhost \
  --host-fuzz-value 127.0.0.1 \
  --smuggling-lite \
  --smuggling-limit 40 \
  --bypass-ip 127.0.0.1 \
  --bypass-ip ::1 \
  --bypass-ip 10.0.0.1 \
  --bypass-ip 192.168.0.1 \
  --all \
  -k \
  --calibrate \
  --calibration-samples 5 \
  --json out_full_aggressive.json \
  --csv out_full_aggressive.csv
```

## Batch

Archivo `targets.txt` (una URL por línea):

```txt
https://target1.tld/admin
https://target2.tld/private
```

Ejecución:

```bash
python -m bypass batch targets.txt \
  --mode all \
  --profile aggressive \
  --guided-combos \
  --host-fuzz \
  --smuggling-lite \
  -k \
  --out-dir out_batch_full
```

## Replay de hallazgos

```bash
python -m bypass replay out_full_aggressive.json \
  --min-confidence medium \
  --max-targets 50 \
  --replay-methods \
  --replay-headers \
  --header-limit 8 \
  -k
```

## Interpretación de resultados

- **Baseline**: estado y tamaño de referencia del target.
- **Tabla principal**: cada intento con payload usado y score.
- **Resumen final**: tamaño normal vs diferencias por status.
- **Outliers**: filas con tamaño o comportamiento diferente son candidatas para replay/manual triage.
- **smuggling_suspected**: señal diferencial para investigar parsing proxy/backend.

## Desarrollo

Ejecutar tests:

```bash
. .venv/bin/activate
python -m pytest -q
```

Lints (si usas Ruff):

```bash
ruff check .
```

