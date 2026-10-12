/**
 * Katana Web Crawler - IndexedDB Storage Engine
 * Handles high-volume URL storage, deduplication, and fast querying.
 */

class KatanaStorage {
  constructor() {
    this.dbName = 'KatanaCrawlerDB';
    this.dbVersion = 2;
    this.db = null;
    this.knownUrlSet = new Set(); // In-memory URL deduplication set
    this.knownSecretMap = new Map(); // In-memory unique secret deduplication map: match -> record
  }

  async init() {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
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
        reject(event.target.error);
      };
    });
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

            const itemSources = Array.isArray(item.sources) && item.sources.length > 0
              ? item.sources
              : (item.sourceUrl ? [{
                  url: item.sourceUrl,
                  type: item.sourceType || 'html',
                  context: item.context || '',
                  discoveredAt: item.discoveredAt || Date.now()
                }] : []);

            if (consolidatedMap.has(item.match)) {
              // Existing secret found: merge locations and mark duplicate for deletion
              const existing = consolidatedMap.get(item.match);
              for (const src of itemSources) {
                if (!existing.sources.some(s => s.url === src.url)) {
                  existing.sources.push(src);
                }
              }
              duplicatesToDelete.push(item.id);
            } else {
              item.sources = itemSources;
              consolidatedMap.set(item.match, item);
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

    const secretsToInsert = [];
    const secretsToUpdate = [];
    const now = Date.now();

    for (const s of secretsList) {
      if (!s || !s.match) continue;

      const locItem = {
        url: s.sourceUrl,
        type: s.sourceType || 'html',
        context: s.context || '',
        discoveredAt: s.discoveredAt || now
      };

      if (this.knownSecretMap.has(s.match)) {
        const existing = this.knownSecretMap.get(s.match);
        if (!Array.isArray(existing.sources)) {
          existing.sources = existing.sourceUrl ? [{
            url: existing.sourceUrl,
            type: existing.sourceType || 'html',
            context: existing.context || '',
            discoveredAt: existing.discoveredAt || now
          }] : [];
        }

        // Avoid adding duplicate location URLs to the same secret
        const alreadyHasUrl = existing.sources.some(loc => loc.url === s.sourceUrl);
        if (!alreadyHasUrl) {
          existing.sources.push(locItem);
          existing.lastDiscoveredAt = now;
          if (!secretsToUpdate.some(u => u.match === existing.match)) {
            secretsToUpdate.push(existing);
          }
        }
      } else {
        const newRecord = {
          ruleName: s.ruleName,
          severity: s.severity || 'info',
          category: s.category || 'General',
          match: s.match,
          masked: s.masked || '••••••••',
          sources: [locItem],
          firstDiscoveredAt: s.discoveredAt || now,
          lastDiscoveredAt: s.discoveredAt || now
        };
        this.knownSecretMap.set(s.match, newRecord);
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
        store.put(item);
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
      const tx = this.db.transaction('secrets', 'readonly');
      const store = tx.objectStore('secrets');
      const req = store.getAll();

      req.onsuccess = () => {
        let results = req.result || [];

        // Normalize legacy format if any row hasn't been migrated
        results = results.map(item => {
          if (!Array.isArray(item.sources) || item.sources.length === 0) {
            item.sources = item.sourceUrl ? [{
              url: item.sourceUrl,
              type: item.sourceType || 'html',
              context: item.context || '',
              discoveredAt: item.discoveredAt || Date.now()
            }] : [];
          }
          return item;
        });

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

  async clearAll() {
    await this.init();
    this.knownUrlSet.clear();
    this.knownSecretMap.clear();
    return new Promise((resolve, reject) => {
      const stores = ['targets', 'discovered_urls'];
      if (this.db.objectStoreNames.contains('secrets')) stores.push('secrets');
      const tx = this.db.transaction(stores, 'readwrite');
      tx.objectStore('targets').clear();
      tx.objectStore('discovered_urls').clear();
      if (this.db.objectStoreNames.contains('secrets')) tx.objectStore('secrets').clear();

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
