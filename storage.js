/**
 * Crawlizer Local Storage Engine (Pure Server-Backed Client)
 * ZERO browser storage: All targets, discovered URLs, secrets,
 * supply chain audits, logs, and settings are stored 100% locally
 * on disk via the Crawlizer Node.js backend (.data/ directory).
 */

class KatanaStorage {
  constructor() {
    this.listeners = new Map();
    this.ws = null;
    this.wsInitialized = false;
    this.initPromise = null;
    this.knownUrlSet = new Set();
    this.purgeBrowserStorage();
  }

  // Purge any legacy browser storage (IndexedDB & localStorage), but PRESERVE user UI preferences (e.g. crawlizer_theme)
  purgeBrowserStorage() {
    if (typeof indexedDB !== 'undefined' && indexedDB.deleteDatabase) {
      try {
        indexedDB.deleteDatabase('KatanaCrawlerDB');
      } catch (e) {}
    }
    if (typeof localStorage !== 'undefined') {
      try {
        // Clear all Crawlizer/Katana crawled data keys from localStorage, preserving theme preferences
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && !k.startsWith('crawlizer_theme') && k !== 'crawlizer_theme' && (k.startsWith('crawlizer') || k.startsWith('katana') || k.startsWith('crawler'))) {
            keysToRemove.push(k);
          }
        }
        keysToRemove.forEach(k => localStorage.removeItem(k));
      } catch (e) {}
    }
    if (typeof sessionStorage !== 'undefined') {
      try {
        const theme = sessionStorage.getItem('crawlizer_theme');
        sessionStorage.clear();
        if (theme) sessionStorage.setItem('crawlizer_theme', theme);
      } catch (e) {}
    }
  }

  getBaseUrl() {
    if (typeof window !== 'undefined' && window.location) {
      const loc = window.location;
      if (loc.protocol && loc.protocol.startsWith('http') && !loc.protocol.startsWith('chrome-extension')) {
        return '';
      }
    }
    return 'http://127.0.0.1:4488';
  }

  isLocalServer() {
    return true;
  }

  on(event, callback) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(callback);
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try { cb(data); } catch (e) { console.warn(e); }
      });
    }
  }

  initLocalServerWs() {
    if (this.wsInitialized) return;
    this.wsInitialized = true;
    try {
      let wsUrl = 'ws://127.0.0.1:4488/ws';
      if (typeof window !== 'undefined' && window.location) {
        const loc = window.location;
        if (loc.protocol && loc.protocol.startsWith('http') && !loc.protocol.startsWith('chrome-extension')) {
          const wsProto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
          wsUrl = `${wsProto}//${loc.host}/ws`;
        }
      }

      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.emit('server:connected', true);
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.emit(msg.type, msg);
        } catch {}
      };

      this.ws.onclose = () => {
        this.emit('server:connected', false);
        this.wsInitialized = false;
        setTimeout(() => this.initLocalServerWs(), 3000);
      };

      this.ws.onerror = () => {
        try { this.ws.close(); } catch {}
      };
    } catch {}
  }

  async init() {
    this.purgeBrowserStorage();
    this.initLocalServerWs();
    return Promise.resolve();
  }

  canonical(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const u = new URL(rawUrl.trim());
      u.hostname = u.hostname.toLowerCase();
      if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) {
        u.port = '';
      }
      u.hash = '';
      let p = u.pathname.replace(/\/+/g, '/');
      if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
      u.pathname = p;
      if (u.search) {
        const params = new URLSearchParams(u.search);
        params.sort();
        const s = params.toString();
        u.search = s ? '?' + s : '';
      }
      return u.toString();
    } catch {
      return rawUrl.trim();
    }
  }

  // --- Seed Targets ---
  async addTargets(targetUrls) {
    const urls = Array.isArray(targetUrls) ? targetUrls : [targetUrls];
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls })
      });
      return await res.json();
    } catch (err) {
      console.warn('[KatanaStorage] addTargets error:', err.message);
      return [];
    }
  }

  async getPendingTargets() {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/targets`);
      const list = await res.json();
      return Array.isArray(list) ? list.filter(t => t.status === 'pending') : [];
    } catch {
      return [];
    }
  }

  async getAllTargets() {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/targets`);
      const list = await res.json();
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  async updateTarget(id, updates) {
    try {
      await fetch(`${this.getBaseUrl()}/api/targets/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      });
    } catch (err) {
      console.warn('[KatanaStorage] updateTarget error:', err.message);
    }
  }

  async clearTargets() {
    try {
      await fetch(`${this.getBaseUrl()}/api/targets`, { method: 'DELETE' });
    } catch {}
  }

  async reactivateAllTargets() {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/targets/reactivate`, { method: 'POST' });
      const data = await res.json();
      return data.count || 0;
    } catch {
      return 0;
    }
  }

  // --- Discovered URLs ---
  async addDiscoveredUrls(urlObjects) {
    if (!urlObjects || urlObjects.length === 0) return 0;
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/urls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(urlObjects)
      });
      const data = await res.json();
      urlObjects.forEach(u => {
        if (u && u.url) this.knownUrlSet.add(this.canonical(u.url));
      });
      return data.count || 0;
    } catch {
      return 0;
    }
  }

  async isUrlKnown(url) {
    if (!url) return false;
    return this.knownUrlSet.has(this.canonical(url));
  }

  async getDiscoveredUrls(filters = {}) {
    try {
      const filterObj = (typeof filters === 'number') ? { limit: filters } : (filters || {});
      const qs = new URLSearchParams();
      if (filterObj.type) qs.set('type', filterObj.type);
      if (filterObj.search) qs.set('search', filterObj.search);
      const res = await fetch(`${this.getBaseUrl()}/api/urls?` + qs.toString());
      let items = await res.json();
      if (!Array.isArray(items)) return [];

      // Additional client-side filtering if needed
      if (filterObj.scope && filterObj.scope !== 'all') {
        items = items.filter(u => u.scope === filterObj.scope);
      }
      if (filterObj.extension && filterObj.extension !== 'all') {
        const ext = filterObj.extension.toLowerCase();
        items = items.filter(u => (u.url || '').toLowerCase().includes(ext));
      }
      if (filterObj.limit && typeof filterObj.limit === 'number' && filterObj.limit > 0) {
        items = items.slice(0, filterObj.limit);
      }
      return items;
    } catch {
      return [];
    }
  }

  async clearDiscoveredUrlsOnly() {
    try {
      await fetch(`${this.getBaseUrl()}/api/urls`, { method: 'DELETE' });
    } catch {}
    this.knownUrlSet.clear();
  }

  // --- Secrets & Findings ---
  async saveSecrets(secretsList) {
    if (!secretsList || secretsList.length === 0) return { newCount: 0, updatedCount: 0 };
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/secrets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(secretsList)
      });
      const data = await res.json();
      return { newCount: data.count || 0, updatedCount: 0 };
    } catch {
      return { newCount: 0, updatedCount: 0 };
    }
  }

  async getSecrets(filters = {}) {
    try {
      const qs = new URLSearchParams();
      if (filters && filters.severity) qs.set('severity', filters.severity);
      if (filters && filters.search) qs.set('search', filters.search);
      const res = await fetch(`${this.getBaseUrl()}/api/secrets?` + qs.toString());
      const items = await res.json();
      return Array.isArray(items) ? items : [];
    } catch {
      return [];
    }
  }

  async clearSecrets() {
    try {
      await fetch(`${this.getBaseUrl()}/api/secrets`, { method: 'DELETE' });
    } catch {}
  }

  // --- Supply Chain Audits ---
  async saveSupplyChainFindings(findingsArray) {
    if (!findingsArray || findingsArray.length === 0) return { newCount: 0, updatedCount: 0 };
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/supply-chain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(findingsArray)
      });
      const data = await res.json();
      return { newCount: data.count || 0, updatedCount: 0 };
    } catch {
      return { newCount: 0, updatedCount: 0 };
    }
  }

  async getSupplyChainFindings(filters = {}) {
    try {
      const qs = new URLSearchParams();
      if (filters && filters.ecosystem) qs.set('ecosystem', filters.ecosystem);
      if (filters && filters.severity) qs.set('severity', filters.severity);
      if (filters && filters.search) qs.set('search', filters.search);
      const res = await fetch(`${this.getBaseUrl()}/api/supply-chain?` + qs.toString());
      let items = await res.json();
      if (!Array.isArray(items)) return [];

      if (filters && filters.severity && filters.severity !== 'all') {
        if (filters.severity === 'critical') items = items.filter(item => item.isUnregistered);
        else if (filters.severity === 'cve') items = items.filter(item => item.advisoriesCount > 0);
        else if (filters.severity === 'safe') items = items.filter(item => !item.isUnregistered && (!item.advisoriesCount || item.advisoriesCount === 0));
        else if (filters.severity === 'exposed') items = items.filter(item => item.type === 'exposed-file');
      }

      items.sort((a, b) => {
        if (a.isUnregistered && !b.isUnregistered) return -1;
        if (!a.isUnregistered && b.isUnregistered) return 1;
        const advA = a.advisoriesCount || 0;
        const advB = b.advisoriesCount || 0;
        if (advA !== advB) return advB - advA;
        return (new Date(b.lastUpdated || 0)) - (new Date(a.lastUpdated || 0));
      });

      return items;
    } catch {
      return [];
    }
  }

  async clearSupplyChainFindings() {
    try {
      await fetch(`${this.getBaseUrl()}/api/supply-chain`, { method: 'DELETE' });
    } catch {}
  }

  // --- Logs ---
  async getLogs(limit = 200) {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/logs?limit=${limit}`);
      const list = await res.json();
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  async clearLogs() {
    try {
      await fetch(`${this.getBaseUrl()}/api/logs`, { method: 'DELETE' });
    } catch {}
  }

  // --- Statistics & Metrics ---
  async getStats() {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/metrics`);
      const metrics = await res.json();
      return {
        totalTargets: metrics.totalTargets || metrics.targetsCount || 0,
        pendingTargets: metrics.pendingTargets || 0,
        crawledTargets: metrics.crawledTargets || 0,
        failedTargets: metrics.failedTargets || 0,
        totalDiscovered: (metrics.urls && metrics.urls.total) || metrics.totalDiscovered || 0,
        totalSecrets: (metrics.secrets && metrics.secrets.total) || metrics.totalSecrets || 0,
        totalSupplyChain: (metrics.supplyChain && metrics.supplyChain.total) || metrics.totalSupplyChain || 0,
        ...metrics
      };
    } catch {
      return {
        totalTargets: 0,
        pendingTargets: 0,
        crawledTargets: 0,
        failedTargets: 0,
        totalDiscovered: 0,
        totalSecrets: 0,
        totalSupplyChain: 0
      };
    }
  }

  // --- Settings & Configuration (Stored in .data/settings.json on disk) ---
  async getSetting(key, defaultValue = null) {
    try {
      const res = await fetch(`${this.getBaseUrl()}/api/settings/${encodeURIComponent(key)}`);
      if (res.ok) {
        const data = await res.json();
        return data.value !== undefined && data.value !== null ? data.value : defaultValue;
      }
    } catch {}
    return defaultValue;
  }

  async saveSetting(key, value) {
    try {
      await fetch(`${this.getBaseUrl()}/api/settings/${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value })
      });
    } catch (err) {
      console.warn('[KatanaStorage] saveSetting error:', err.message);
    }
    return value;
  }

  // --- Complete Wipe ---
  async clearAll() {
    this.purgeBrowserStorage();
    this.knownUrlSet.clear();
    try {
      await fetch(`${this.getBaseUrl()}/api/wipe`, { method: 'POST' });
    } catch {}
  }
}

// Global storage singleton
if (typeof window !== 'undefined') {
  window.katanaStorage = new KatanaStorage();
}
