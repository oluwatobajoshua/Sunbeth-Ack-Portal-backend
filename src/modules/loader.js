const fs = require('fs');
const path = require('path');

/**
 * Loads module routers under src/modules/* and mounts to /api/v1/<name>.
 * Respects feature flags via featureFlagGetter(`module_<name>_enabled`) when provided.
 * A module is recognized if it contains routes.js and module.json.
 */
function loadAndMountModules(app, { featureFlagGetter } = {}) {
  try {
    const modsRoot = path.join(__dirname);
    const entries = fs.readdirSync(modsRoot, { withFileTypes: true });
    entries.forEach((ent) => {
      if (!ent.isDirectory()) return;
      const name = ent.name;
      if (name === 'loader.js') return;
      const modDir = path.join(modsRoot, name);
      const routesFile = path.join(modDir, 'routes.js');
      const manifestFile = path.join(modDir, 'module.json');
      if (!fs.existsSync(routesFile) || !fs.existsSync(manifestFile)) return;
      const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
      const flagKey = manifest.featureFlag || `module_${name}_enabled`;
      let enabled = true;
      if (typeof featureFlagGetter === 'function') {
        const raw = featureFlagGetter(flagKey, '1');
        enabled = String(raw) === '1' || String(raw).toLowerCase() === 'true';
      }
      if (!enabled) return;
  // eslint-disable-next-line import/no-dynamic-require, global-require
  // Use absolute path to reliably require the router file on Windows/Linux
  const router = require(routesFile);
      const base = manifest.routeBase || `/api/v1/${name}`;
      app.use(base, router);
      console.log(`[modules] mounted ${name} at ${base}`);
    });
  } catch (e) {
    console.warn('[modules] loader failed (non-fatal):', e.message || e);
  }
}

function listModules({ featureFlagGetter } = {}) {
  const mods = [];
  try {
    const modsRoot = path.join(__dirname);
    const entries = fs.readdirSync(modsRoot, { withFileTypes: true });
    entries.forEach((ent) => {
      if (!ent.isDirectory()) return;
      const name = ent.name;
      if (name === 'loader.js') return;
      const modDir = path.join(modsRoot, name);
      const manifestFile = path.join(modDir, 'module.json');
      if (!fs.existsSync(manifestFile)) return;
      const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
      const flagKey = manifest.featureFlag || `module_${name}_enabled`;
      let enabled = true;
      if (typeof featureFlagGetter === 'function') {
        const raw = featureFlagGetter(flagKey, '1');
        enabled = String(raw) === '1' || String(raw).toLowerCase() === 'true';
      }
      mods.push({
        name,
        title: manifest.title || name,
        version: manifest.version || '0.1.0',
        routeBase: manifest.routeBase || `/api/v1/${name}`,
        adminRoute: manifest.adminRoute || `/admin/${name}`,
        featureFlag: flagKey,
        homeRoute: manifest.homeRoute || undefined,
        enabled
      });
    });
  } catch (e) {
    console.warn('[modules] list failed (non-fatal):', e.message || e);
  }
  return mods;
}

module.exports = { loadAndMountModules, listModules };
