// src/jobs/blocklist.job.js
// Tarea programada: actualizar blocklists cada 24 horas con node-cron

const cron = require('node-cron');
const { loadBlocklists } = require('../services/reputation.service');

function startBlocklistJob() {
  // Cargar inmediatamente al iniciar
  loadBlocklists().catch(err => console.warn('[blocklist.job] Carga inicial falló:', err.message));

  // Actualizar todos los días a las 3:00 AM
  cron.schedule('0 3 * * *', () => {
    console.log('[blocklist.job] Actualizando blocklists...');
    loadBlocklists().catch(err => console.warn('[blocklist.job] Error:', err.message));
  });

  console.log('[blocklist.job] Programado: actualización diaria a las 03:00');
}

module.exports = { startBlocklistJob };
