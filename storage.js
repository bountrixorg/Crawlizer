/**
 * Katana Web Crawler - IndexedDB Storage Engine
 * Handles high-volume URL storage, deduplication, and fast querying.
 */

class KatanaStorage {
  constructor() {
    this.dbName = 'KatanaCrawlerDB';
    this.dbVersion = 3;
    this.db = null;
    this.initPromise = null;
    this.knownUrlSet = new Set(); // In-memory URL deduplication set
    this.knownSecretMap = new Map(); // In-memory unique secret deduplication map: match -> record
    this.knownSupplyChainMap = new Map(); // In-memory supply chain deduplication map: key -> record
  }

  async init() {
    if (this.db) return this.db;
    if (this.initPromise) return this.initPromise;

    this.initPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;

        // Targets store (the seed URLs to crawl)
        if (!db.objectStoreNames.contains('targets')) {
          const targetStore = db.createObjectStore('targets', { keyPath: 'id', autoIncrement: true });
          targetStore.createIndex('url', 'url', { unique: false });
          targetStore.createIndex('status', 'status', { unique: false });
        }

        // Discovered URLs store
        if (!db.objectStoreNames.contains('discovered_urls')) {
          const urlStore = db.createObjectStore('discovered_urls', { keyPath: 'id', autoIncrement: true });
          urlStore.createIndex('url', 'url', { unique: false });
          urlStore.createIndex('type', 'type', { unique: false });
          urlStore.createIndex('scope', 'scope', { unique: false });
          urlStore.createIndex('sourceUrl', 'sourceUrl', { unique: false });
          urlStore.createIndex('discoveredAt', 'discoveredAt', { unique: false });
        }

        // Secrets & Sensitive Findings store
        if (!db.objectStoreNames.contains('secrets')) {
          const secretStore = db.createObjectStore('secrets', { keyPath: 'id', autoIncrement: true });
          secretStore.createIndex('ruleName', 'ruleName', { unique: false });
          secretStore.createIndex('severity', 'severity', { unique: false });
          secretStore.createIndex('category', 'category', { unique: false });
          secretStore.createIndex('sourceUrl', 'sourceUrl', { unique: false });
          secretStore.createIndex('sourceType', 'sourceType', { unique: false });
          secretStore.createIndex('discoveredAt', 'discoveredAt', { unique: false });
        }

        // Supply Chain & NPM Dependencies store
        if (!db.objectStoreNames.contains('supply_chain')) {
          const supplyStore = db.createObjectStore('supply_chain', { keyPath: 'id', autoIncrement: true });
          supplyStore.createIndex('key', 'key', { unique: false });
          supplyStore.createIndex('name', 'name', { unique: false });
          supplyStore.createIndex('ecosystem', 'ecosystem', { unique: false });
          supplyStore.createIndex('riskLevel', 'riskLevel', { unique: false });
          supplyStore.createIndex('isUnregistered', 'isUnregistered', { unique: false });
          supplyStore.createIndex('type', 'type', { unique: false });
          supplyStore.createIndex('discoveredAt', 'discoveredAt', { unique: false });
        }

        // Settings & Sessions store
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'key' });
        }
      };

      request.onsuccess = async (event) => {
        this.db = event.target.result;
        await this.loadUrlCache();
        resolve(this.db);
      };

      request.onerror = (event) => {
        console.error('IndexedDB open error:', event.target.error);
        this.initPromise = null;
        reject(event.target.error);
      };
    });

    return this.initPromise;
  }

  // Canonical URL normalizer for persistent deduplication
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

  // Load existing URLs and Secrets into in-memory Sets/Maps for instant O(1) deduplication
  async loadUrlCache() {
    this.knownUrlSet.clear();
    this.knownSecretMap.clear();

    await new Promise((resolve) => {
      const tx = this.db.transaction('discovered_urls', 'readonly');
      const store = tx.objectStore('discovered_urls');
      const req = store.openCursor();

      req.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) {
          const c = this.canonical(cursor.value.url);
          if (c) this.knownUrlSet.add(c);
          cursor.continue();
        } else {
          resolve();
        }
      };

      req.onerror = () => resolve();
    });

    if (this.db.objectStoreNames.contains('secrets')) {
      await new Promise((resolve) => {
        const tx = this.db.transaction('secrets', 'readwrite');
        const store = tx.objectStore('secrets');
        const req = store.getAll();

        req.onsuccess = () => {
          const all = req.result || [];
          const consolidatedMap = new Map();
          const duplicatesToDelete = [];

          for (const item of all) {
            if (!item || !item.match) continue;
            const matchKey = item.match.trim();
            if (!matchKey) continue;

            const itemSources = Array.isArray(item.sources) && item.sources.length > 0
              ? item.sources
              : (item.sourceUrl ? [{
                  url: item.sourceUrl,
                  type: item.sourceType || 'html',
                  context: item.context || '',
                  discoveredAt: item.discoveredAt || Date.now()
                }] : []);

            if (consolidatedMap.has(matchKey)) {
              // Existing secret found: merge locations and mark duplicate for deletion
              const existing = consolidatedMap.get(matchKey);
              for (const src of itemSources) {
                if (src.url && !existing.sources.some(s => s.url === src.url)) {
                  existing.sources.push(src);
                }
              }
              if (item.id && item.id !== existing.id) {
                duplicatesToDelete.push(item.id);
              }
            } else {
              item.match = matchKey;
              item.sources = itemSources;
              consolidatedMap.set(matchKey, item);
            }
          }

          // Clean up duplicates from DB and update consolidated records
          for (const delId of duplicatesToDelete) {
            store.delete(delId);
          }
          for (const [match, record] of consolidatedMap.entries()) {
            store.put(record);
            this.knownSecretMap.set(match, record);
          }

    if (this.db.objectStoreNames.contains('supply_chain')) {
      await new Promise((resolve) => {
        const tx = this.db.transaction('supply_chain', 'readonly');
        const store = tx.objectStore('supply_chain');
        const req = store.getAll();

        req.onsuccess = () => {
          const all = req.result || [];
          for (const item of all) {
            if (!item || !item.key) continue;
            this.knownSupplyChainMap.set(item.key, item);
          }
          resolve();
        };
        req.onerror = () => resolve();
      });
    }
  }

  // Save new seed targets from .txt
  async addTargets(targetUrls) {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('targets', 'readwrite');
      const store = tx.objectStore('targets');
      const now = Date.now();

      for (const url of targetUrls) {
        store.add({
          url: url.trim(),
          status: 'pending', // pending, crawling, completed, failed
          addedAt: now,
          crawledAt: null,
          error: null,
          discoveredCount: 0
        });
      }

      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async getPendingTargets() {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('targets', 'readonly');
      const store = tx.objectStore('targets');
      const index = store.index('status');
      const req = index.getAll('pending');

      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  }

  async getAllTargets() {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('targets', 'readonly');
      const store = tx.objectStore('targets');
      const req = store.getAll();

      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  }

  async updateTarget(id, updates) {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('targets', 'readwrite');
      const store = tx.objectStore('targets');
      const req = store.get(id);

      req.onsuccess = () => {
        const record = req.result;
        if (record) {
          Object.assign(record, updates);
          store.put(record);
        }
      };

      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  // Batch insert discovered URLs with deduplication
  async addDiscoveredUrls(urlObjects) {
    await this.init();
    const newItems = [];
    const now = Date.now();

    for (const item of urlObjects) {
      const canonical = this.canonical(item.url);
      if (!canonical) continue;

      if (!this.knownUrlSet.has(canonical)) {
        this.knownUrlSet.add(canonical);
        newItems.push({
          url: canonical,
          sourceUrl: item.sourceUrl || '',
          targetUrl: item.targetUrl || '',
          type: item.type || 'endpoint',
          scope: item.scope || 'in-scope',
          depth: item.depth || 1,
          statusCode: item.statusCode || null,
          discoveredAt: now
        });
      }
    }

    if (newItems.length === 0) return 0;

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('discovered_urls', 'readwrite');
      const store = tx.objectStore('discovered_urls');

      for (const item of newItems) {
        store.add(item);
      }

      tx.oncomplete = () => resolve(newItems.length);
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async isUrlKnown(url) {
    return this.knownUrlSet.has(url.trim());
  }

  async getDiscoveredUrls(filters = {}) {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('discovered_urls', 'readonly');
      const store = tx.objectStore('discovered_urls');
      const req = store.getAll();

      req.onsuccess = () => {
        let results = req.result || [];

        // Apply filters
        if (filters.search) {
          const q = filters.search.toLowerCase();
          results = results.filter(item => item.url.toLowerCase().includes(q) || (item.sourceUrl && item.sourceUrl.toLowerCase().includes(q)));
        }

        if (filters.type && filters.type !== 'all') {
          const ft = filters.type.toLowerCase();
          results = results.filter(item => {
            const it = (item.type || '').toLowerCase();
            if (ft === 'subdomain') return it.includes('subdomain');
            if (ft === 'button-click') return it.includes('button') || it.includes('click');
            if (ft === 'js-endpoint') return it.includes('endpoint') || it.includes('regex') || it.includes('comment') || it.includes('hydration');
            if (ft === 'network-api') return it.includes('network') || it.includes('api') || it.includes('xhr') || it.includes('fetch');
            if (ft === 'script-bundle') return it.includes('script') || it.includes('bundle') || it.includes('js');
            if (ft === 'html-link') return it.includes('link') || it.includes('dom') || it.includes('anchor') || it.includes('html');
            if (ft === 'form-action') return it.includes('form');
            if (ft === 'robots.txt') return it.includes('robots');
            if (ft === 'sitemap') return it.includes('sitemap');
            return it.includes(ft);
          });
        }

        if (filters.scope && filters.scope !== 'all') {
          results = results.filter(item => item.scope === filters.scope);
        }

        if (filters.extension && filters.extension !== 'all') {
          const ext = filters.extension.toLowerCase();
          results = results.filter(item => {
            try {
              const u = new URL(item.url);
              return u.pathname.toLowerCase().endsWith(ext);
            } catch {
              return item.url.toLowerCase().includes(ext);
            }
          });
        }

        resolve(results);
      };

      req.onerror = (e) => reject(e.target.error);
    });
  }

  // ==========================================
  // Secrets & Sensitive Findings Operations
  // ==========================================
  async saveSecrets(secretsList) {
    if (!secretsList || secretsList.length === 0) return { newCount: 0, updatedCount: 0 };
    await this.init();

    const now = Date.now();

    // 1. Strictly consolidate incoming batch by trimmed match key
    const incomingConsolidated = new Map();
    for (const s of secretsList) {
      if (!s || !s.match) continue;
      const matchKey = s.match.trim();
      if (!matchKey) continue;

      const locItem = {
        url: s.sourceUrl || '',
        type: s.sourceType || 'html',
        context: s.context || '',
        discoveredAt: s.discoveredAt || now
      };

      if (incomingConsolidated.has(matchKey)) {
        const item = incomingConsolidated.get(matchKey);
        if (locItem.url && !item.sources.some(l => l.url === locItem.url)) {
          item.sources.push(locItem);
        }
      } else {
        incomingConsolidated.set(matchKey, {
          ruleName: s.ruleName,
          severity: s.severity || 'info',
          category: s.category || 'General',
          match: matchKey,
          masked: s.masked || '••••••••',
          sources: locItem.url ? [locItem] : [],
          discoveredAt: s.discoveredAt || now
        });
      }
    }

    const secretsToInsert = [];
    const secretsToUpdate = [];

    // 2. Process against knownSecretMap
    for (const [matchKey, incoming] of incomingConsolidated.entries()) {
      if (this.knownSecretMap.has(matchKey)) {
        const existing = this.knownSecretMap.get(matchKey);
        if (!Array.isArray(existing.sources)) {
          existing.sources = existing.sourceUrl ? [{
            url: existing.sourceUrl,
            type: existing.sourceType || 'html',
            context: existing.context || '',
            discoveredAt: existing.discoveredAt || now
          }] : [];
        }

        let locAdded = false;
        for (const loc of incoming.sources) {
          if (loc.url && !existing.sources.some(l => l.url === loc.url)) {
            existing.sources.push(loc);
            locAdded = true;
          }
        }

        if (locAdded) {
          existing.lastDiscoveredAt = now;
          // ONLY queue for update if it already has a database ID and is NOT already in secretsToUpdate
          if (existing.id && !secretsToUpdate.some(u => u.id === existing.id)) {
            secretsToUpdate.push(existing);
          }
        }
      } else {
        const newRecord = {
          ruleName: incoming.ruleName,
          severity: incoming.severity,
          category: incoming.category,
          match: incoming.match,
          masked: incoming.masked,
          sources: incoming.sources,
          firstDiscoveredAt: incoming.discoveredAt || now,
          lastDiscoveredAt: incoming.discoveredAt || now
        };
        this.knownSecretMap.set(matchKey, newRecord);
        secretsToInsert.push(newRecord);
      }
    }

    if (secretsToInsert.length === 0 && secretsToUpdate.length === 0) {
      return { newCount: 0, updatedCount: 0 };
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('secrets', 'readwrite');
      const store = tx.objectStore('secrets');

      for (const item of secretsToInsert) {
        const req = store.add(item);
        req.onsuccess = (e) => {
          item.id = e.target.result;
        };
      }

      for (const item of secretsToUpdate) {
        if (item.id) {
          store.put(item);
        }
      }

      tx.oncomplete = () => resolve({
        newCount: secretsToInsert.length,
        updatedCount: secretsToUpdate.length
      });
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async getSecrets(filters = {}) {
    await this.init();
    return new Promise((resolve, reject) => {
      if (!this.db.objectStoreNames.contains('secrets')) {
        return resolve([]);
      }
      const tx = this.db.transaction('secrets', 'readwrite');
      const store = tx.objectStore('secrets');
      const req = store.getAll();

      req.onsuccess = () => {
        let rawResults = req.result || [];

        // STRICT DEDUPLICATION & RECONCILIATION
        const consolidatedMap = new Map();
        const duplicatesToDelete = [];

        for (const item of rawResults) {
          if (!item || !item.match) continue;
          const matchKey = item.match.trim();
          if (!matchKey) continue;

          const itemSources = Array.isArray(item.sources) && item.sources.length > 0
            ? item.sources
            : (item.sourceUrl ? [{
                url: item.sourceUrl,
                type: item.sourceType || 'html',
                context: item.context || '',
                discoveredAt: item.discoveredAt || Date.now()
              }] : []);

          if (consolidatedMap.has(matchKey)) {
            // Duplicate found in database! Merge sources and mark duplicate ID for deletion
            const existing = consolidatedMap.get(matchKey);
            for (const src of itemSources) {
              if (src.url && !existing.sources.some(s => s.url === src.url)) {
                existing.sources.push(src);
              }
            }
            if (item.id && item.id !== existing.id) {
              duplicatesToDelete.push(item.id);
            }
          } else {
            item.match = matchKey;
            item.sources = itemSources;
            consolidatedMap.set(matchKey, item);
          }
        }

        // Clean up duplicate rows from IndexedDB so the database is self-healing
        for (const delId of duplicatesToDelete) {
          store.delete(delId);
        }
        for (const [matchKey, record] of consolidatedMap.entries()) {
          this.knownSecretMap.set(matchKey, record);
          if (duplicatesToDelete.length > 0) {
            store.put(record);
          }
        }

        let results = Array.from(consolidatedMap.values());

        if (filters.search) {
          const q = filters.search.toLowerCase();
          results = results.filter(item => 
            (item.ruleName && item.ruleName.toLowerCase().includes(q)) || 
            (item.match && item.match.toLowerCase().includes(q)) || 
            (item.category && item.category.toLowerCase().includes(q)) ||
            (item.sources && item.sources.some(src => 
              (src.url && src.url.toLowerCase().includes(q)) || 
              (src.context && src.context.toLowerCase().includes(q))
            ))
          );
        }

        if (filters.severity && filters.severity !== 'all') {
          results = results.filter(item => item.severity === filters.severity);
        }

        if (filters.category && filters.category !== 'all') {
          results = results.filter(item => item.category === filters.category);
        }

        if (filters.sourceType && filters.sourceType !== 'all') {
          results = results.filter(item => 
            item.sources && item.sources.some(src => (src.type || '').toLowerCase() === filters.sourceType.toLowerCase())
          );
        }

        // Sort: critical > high > medium > low > info > date desc
        const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        results.sort((a, b) => {
          const sa = sevOrder[a.severity] || 0;
          const sb = sevOrder[b.severity] || 0;
          if (sa !== sb) return sb - sa;
          const timeA = a.lastDiscoveredAt || a.firstDiscoveredAt || a.discoveredAt || 0;
          const timeB = b.lastDiscoveredAt || b.firstDiscoveredAt || b.discoveredAt || 0;
          return timeB - timeA;
        });

        resolve(results);
      };

      req.onerror = (e) => reject(e.target.error);
    });
  }

  async clearSecrets() {
    await this.init();
    this.knownSecretMap.clear();
    return new Promise((resolve, reject) => {
      if (!this.db.objectStoreNames.contains('secrets')) return resolve();
      const tx = this.db.transaction('secrets', 'readwrite');
      tx.objectStore('secrets').clear();
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async getStats() {
    await this.init();
    const targets = await this.getAllTargets();
    const totalDiscovered = this.knownUrlSet.size;
    const totalSecrets = this.knownSecretMap.size;

    const stats = {
      totalTargets: targets.length,
      pendingTargets: targets.filter(t => t.status === 'pending').length,
      crawledTargets: targets.filter(t => t.status === 'completed').length,
      failedTargets: targets.filter(t => t.status === 'failed').length,
      totalDiscovered: totalDiscovered,
      totalSecrets: totalSecrets
    };

    return stats;
  }

  async saveSupplyChainFindings(findingsArray) {
    if (!findingsArray || findingsArray.length === 0) return { newCount: 0, updatedCount: 0 };
    await this.init();

    const now = Date.now();
    const incomingConsolidated = new Map();

    for (const f of findingsArray) {
      if (!f) continue;
      const key = f.key || (f.type === 'exposed-file' ? `exposed:${f.path}` : `${f.ecosystem || 'npm'}:${f.name}`);
      const locItem = {
        url: f.sourceUrl || '',
        type: f.sourceType || 'code',
        context: f.context || '',
        discoveredAt: f.discoveredAt || now
      };

      if (incomingConsolidated.has(key)) {
        const item = incomingConsolidated.get(key);
        if (locItem.url && !item.sources.some(s => s.url === locItem.url)) {
          item.sources.push(locItem);
        }
      } else {
        incomingConsolidated.set(key, {
          key,
          type: f.type || 'package',
          name: f.name || f.path || 'unknown',
          version: f.version || '',
          ecosystem: f.ecosystem || 'npm',
          path: f.path || '',
          status: f.status || 200,
          contentType: f.contentType || '',
          riskLevel: f.riskLevel || (f.isUnregistered ? 'CRITICAL' : 'LOW'),
          riskReasons: f.riskReasons || [],
          isUnregistered: Boolean(f.isUnregistered),
          advisories: f.advisories || [],
          advisoriesCount: f.advisoriesCount || (f.advisories ? f.advisories.length : 0),
          weeklyDownloads: f.weeklyDownloads != null ? f.weeklyDownloads : 0,
          sources: locItem.url ? [locItem] : [],
          discoveredAt: f.discoveredAt || now
        });
      }
    }

    const toInsert = [];
    const toUpdate = [];

    for (const [key, incoming] of incomingConsolidated.entries()) {
      if (this.knownSupplyChainMap.has(key)) {
        const existing = this.knownSupplyChainMap.get(key);
        let locAdded = false;
        for (const loc of incoming.sources) {
          if (loc.url && !existing.sources.some(l => l.url === loc.url)) {
            existing.sources.push(loc);
            locAdded = true;
          }
        }
        if (incoming.isUnregistered !== undefined) existing.isUnregistered = incoming.isUnregistered;
        if (incoming.riskLevel) existing.riskLevel = incoming.riskLevel;
        if (incoming.advisories && incoming.advisories.length > 0) {
          existing.advisories = incoming.advisories;
          existing.advisoriesCount = incoming.advisoriesCount;
        }
        if (incoming.weeklyDownloads) existing.weeklyDownloads = incoming.weeklyDownloads;
        if (incoming.riskReasons && incoming.riskReasons.length > 0) existing.riskReasons = incoming.riskReasons;

        if (locAdded || incoming.isUnregistered) {
          existing.lastDiscoveredAt = now;
          if (existing.id && !toUpdate.some(u => u.id === existing.id)) {
            toUpdate.push(existing);
          }
        }
      } else {
        const newRecord = {
          ...incoming,
          firstDiscoveredAt: incoming.discoveredAt || now,
          lastDiscoveredAt: incoming.discoveredAt || now
        };
        this.knownSupplyChainMap.set(key, newRecord);
        toInsert.push(newRecord);
      }
    }

    if (toInsert.length === 0 && toUpdate.length === 0) {
      return { newCount: 0, updatedCount: 0 };
    }

    return new Promise((resolve, reject) => {
      if (!this.db.objectStoreNames.contains('supply_chain')) {
        return resolve({ newCount: 0, updatedCount: 0 });
      }
      const tx = this.db.transaction('supply_chain', 'readwrite');
      const store = tx.objectStore('supply_chain');

      for (const item of toInsert) {
        const req = store.add(item);
        req.onsuccess = (e) => {
          item.id = e.target.result;
        };
      }

      for (const item of toUpdate) {
        if (item.id) store.put(item);
      }

      tx.oncomplete = () => resolve({
        newCount: toInsert.length,
        updatedCount: toUpdate.length
      });
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async getSupplyChainFindings(filters = {}) {
    await this.init();
    return new Promise((resolve, reject) => {
      if (!this.db.objectStoreNames.contains('supply_chain')) {
        return resolve([]);
      }
      const tx = this.db.transaction('supply_chain', 'readonly');
      const store = tx.objectStore('supply_chain');
      const req = store.getAll();

      req.onsuccess = () => {
        let results = req.result || [];

        if (filters.search) {
          const q = filters.search.toLowerCase();
          results = results.filter(item =>
            (item.name && item.name.toLowerCase().includes(q)) ||
            (item.path && item.path.toLowerCase().includes(q)) ||
            (item.ecosystem && item.ecosystem.toLowerCase().includes(q)) ||
            (item.sources && item.sources.some(src => (src.url && src.url.toLowerCase().includes(q))))
          );
        }

        if (filters.ecosystem && filters.ecosystem !== 'all') {
          results = results.filter(item => (item.ecosystem || '').toLowerCase() === filters.ecosystem.toLowerCase());
        }

        if (filters.severity && filters.severity !== 'all') {
          if (filters.severity === 'critical') results = results.filter(item => item.isUnregistered);
          else if (filters.severity === 'cve') results = results.filter(item => item.advisoriesCount > 0);
          else if (filters.severity === 'safe') results = results.filter(item => !item.isUnregistered && (!item.advisoriesCount || item.advisoriesCount === 0));
          else if (filters.severity === 'exposed') results = results.filter(item => item.type === 'exposed-file');
        }

        // Sort: Critical (unregistered) > CVE count desc > date desc
        results.sort((a, b) => {
          if (a.isUnregistered && !b.isUnregistered) return -1;
          if (!a.isUnregistered && b.isUnregistered) return 1;
          const advA = a.advisoriesCount || 0;
          const advB = b.advisoriesCount || 0;
          if (advA !== advB) return advB - advA;
          return (b.lastDiscoveredAt || 0) - (a.lastDiscoveredAt || 0);
        });

        resolve(results);
      };

      req.onerror = (e) => reject(e.target.error);
    });
  }

  async clearSupplyChainFindings() {
    await this.init();
    this.knownSupplyChainMap.clear();
    return new Promise((resolve, reject) => {
      if (!this.db.objectStoreNames.contains('supply_chain')) return resolve();
      const tx = this.db.transaction('supply_chain', 'readwrite');
      tx.objectStore('supply_chain').clear();
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async clearAll() {
    await this.init();
    this.knownUrlSet.clear();
    this.knownSecretMap.clear();
    this.knownSupplyChainMap.clear();
    return new Promise((resolve, reject) => {
      const stores = ['targets', 'discovered_urls'];
      if (this.db.objectStoreNames.contains('secrets')) stores.push('secrets');
      if (this.db.objectStoreNames.contains('supply_chain')) stores.push('supply_chain');
      const tx = this.db.transaction(stores, 'readwrite');
      tx.objectStore('targets').clear();
      tx.objectStore('discovered_urls').clear();
      if (this.db.objectStoreNames.contains('secrets')) tx.objectStore('secrets').clear();
      if (this.db.objectStoreNames.contains('supply_chain')) tx.objectStore('supply_chain').clear();

      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async clearDiscoveredUrlsOnly() {
    await this.init();
    this.knownUrlSet.clear();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('discovered_urls', 'readwrite');
      tx.objectStore('discovered_urls').clear();

      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  async getSetting(key, defaultValue = null) {
    await this.init();
    return new Promise((resolve) => {
      const tx = this.db.transaction('settings', 'readonly');
      const store = tx.objectStore('settings');
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result ? req.result.value : defaultValue);
      req.onerror = () => resolve(defaultValue);
    });
  }

  async saveSetting(key, value) {
    await this.init();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('settings', 'readwrite');
      const store = tx.objectStore('settings');
      store.put({ key, value });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }
}

// Global storage singleton for extension pages
window.katanaStorage = new KatanaStorage();
