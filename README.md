# NetWatch — Monitor de Conexiones de Red

Dashboard web local para monitorear conexiones de red activas, resolver FQDN vía DNS e historial de conexiones.

---

## 🚀 Inicio Rápido (Windows Nativo — Recomendado para Fase 1)

En Windows, Docker usa WSL2 como VM, por lo que el contenedor no puede ver las conexiones reales del equipo host directamente. Por eso para Fase 1 se recomienda correr Node.js directamente en Windows.

### 1. Instalar prerequisitos

1. **Node.js 22 LTS** → https://nodejs.org (marcar "Add to PATH")
2. **Git** → https://git-scm.com
3. **VS Code** → https://code.visualstudio.com
4. **Docker Desktop** → https://docker.com/products/docker-desktop (para Fase 2+)

### 2. Configurar el proyecto

```bash
# 1. Clonar o descomprimir el proyecto
cd C:\Users\TuUsuario\Projects
# (si usas git: git clone <repo>)

# 2. Entrar al directorio
cd netwatch

# 3. Instalar dependencias
npm install

# 4. Crear archivo de configuración
copy .env.example .env
# (editar .env si necesitas cambiar el puerto)

# 5. Iniciar la aplicación
npm start
```

### 3. Abrir en el navegador

```
http://localhost:3000
```

---

## 🐳 Inicio con Docker (Windows — limitado a conexiones de WSL2)

```bash
# Construir imagen
docker-compose build

# Iniciar contenedor
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener
docker-compose down
```

> **Nota**: En Windows con Docker Desktop, las conexiones mostradas son las del entorno WSL2, no las del host Windows. Para ver las conexiones reales del equipo, usa `npm start` directamente.

---

## 🐧 Inicio con Docker (Linux — funcionalidad completa)

```bash
docker-compose up -d
```

En Linux, `network_mode: host` permite al contenedor leer las conexiones reales del sistema operativo.

---

## 📁 Estructura del Proyecto

```
netwatch/
├── src/
│   ├── server.js              # Punto de entrada Express
│   ├── routes/
│   │   └── api.js             # Endpoints REST /api/v1/
│   ├── services/
│   │   ├── netstat.service.js # Lee conexiones del OS
│   │   ├── dns.service.js     # Resolución DNS + caché
│   │   └── logger.service.js  # Persistencia en SQLite
│   └── db/
│       └── database.js        # Inicialización SQLite
├── public/
│   ├── index.html             # UI principal
│   ├── css/style.css          # Estilos
│   └── js/app.js              # Lógica frontend
├── data/                      # SQLite (generado automáticamente)
├── .env.example               # Plantilla de configuración
├── .gitignore
├── Dockerfile
├── docker-compose.yml
└── package.json
```

---

## 🔌 API REST

| Método | Endpoint                    | Descripción                          |
|--------|-----------------------------|--------------------------------------|
| GET    | `/api/v1/connections`       | Conexiones activas + DNS             |
| GET    | `/api/v1/resolve/:ip`       | Resolver una IP a FQDN               |
| GET    | `/api/v1/history`           | Historial de conexiones              |
| GET    | `/api/v1/history/ips`       | IPs únicas vistas                    |
| GET    | `/api/v1/stats`             | Estadísticas generales               |
| DELETE | `/api/v1/cache/dns/:ip`     | Invalidar caché DNS de una IP        |

### Parámetros de `/api/v1/history`
- `?limit=100` — máximo registros (default 100, max 500)
- `?ip=1.2.3.4` — filtrar por IP remota
- `?since=2024-01-01T00:00:00Z` — desde fecha ISO

### Parámetros de `/api/v1/resolve/:ip`
- `?force=1` — ignorar caché y re-consultar DNS

---

## ⚙️ Variables de Entorno (.env)

| Variable               | Default                   | Descripción                     |
|------------------------|---------------------------|---------------------------------|
| `PORT`                 | `3000`                    | Puerto del servidor             |
| `HOST`                 | `127.0.0.1`               | Bind address (solo localhost)   |
| `DB_PATH`              | `./data/netwatch.db`      | Ruta a la base de datos SQLite  |
| `DNS_CACHE_TTL`        | `300`                     | Segundos de validez caché DNS   |
| `DEFAULT_REFRESH_INTERVAL` | `5`                  | Intervalo auto-refresh (seg)    |

---

## 🗺️ Roadmap

### ✅ Fase 1 (actual)
- Ver conexiones de red activas en tiempo real
- Resolución DNS reversa (PTR) con caché inteligente
- Historial en SQLite
- Auto-refresh configurable
- Docker ready

### 🔵 Fase 2 (próxima)
- Geolocalización de IPs (ipinfo.io)
- Reputación de IPs (AbuseIPDB)
- Caché DNS enriquecida con país/ASN
- Filtros avanzados

### 🔴 Fase 3 (corporativo)
- Escaneo de puertos (nmap integration)
- Alertas automáticas por IP desconocida
- Autenticación + roles de usuario
- HTTPS + nginx reverse proxy
- Multi-host monitoring

---

## 🔒 Seguridad

- La app solo escucha en `127.0.0.1` (no accesible desde la red)
- Las API keys van en `.env` (nunca en el código)
- `.gitignore` excluye `.env`, `*.db` y `node_modules`
- El contenedor Docker corre con usuario no-root
- CORS configurado para aceptar solo localhost

---

## 🐛 Troubleshooting

**"EACCES: permission denied" en Linux**
```bash
sudo node src/server.js
# o dar permisos a node para netstat:
sudo setcap cap_net_raw+ep $(which node)
```

**Las conexiones no aparecen en Windows**
- Asegúrate de correr `npm start` como Administrador para que netstat devuelva los PIDs.

**Puerto 3000 ocupado**
```bash
# Cambiar en .env:
PORT=3001
```
