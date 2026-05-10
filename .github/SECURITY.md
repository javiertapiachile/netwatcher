# Política de Seguridad — NetWatch

## Versiones soportadas

| Versión | Soporte de seguridad |
|---------|---------------------|
| 2.x     | ✅ Activo            |
| 1.x     | ⚠️ Solo críticos     |

## Reportar una vulnerabilidad

Si encuentras una vulnerabilidad de seguridad en NetWatch:

1. **NO** abras un Issue público en GitHub
2. Envía un email privado al maintainer del repositorio
3. Incluye:
   - Descripción detallada de la vulnerabilidad
   - Pasos para reproducirla
   - Impacto potencial estimado
   - Versión afectada

Recibirás respuesta en un máximo de 72 horas.

## Herramientas de seguridad activas

- **Dependabot** — actualización automática de dependencias vulnerables
- **CodeQL** — análisis estático de código (SAST)
- **GitLeaks** — detección de secretos en commits
- **npm audit** — auditoría de supply chain en cada push
- **License checker** — verificación de licencias de dependencias

## Qué NO incluir en commits

- Archivos `.env` con valores reales
- API keys o tokens
- Contraseñas o hashes de contraseñas
- Certificados o claves privadas (`.pem`, `.key`, `.p12`)
- Archivos de base de datos (`.db`)
