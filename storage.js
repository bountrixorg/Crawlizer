/**
 * Katana Web Crawler - IndexedDB Storage Engine
 * Handles high-volume URL storage, deduplication, and fast querying.
 */

class KatanaStorage {
  constructor() {
    this.dbName = 'KatanaCrawlerDB';
    this.dbVersion = 1;
    this.db = null;
    this.knownUrlSet = new Set(); // In-memory deduplication set
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

  // Load existing URLs into in-memory Set for instant O(1) deduplication
  async loadUrlCache() {
    this.knownUrlSet.clear();
    return new Promise((resolve) => {
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

  async getStats() {
    await this.init();
    const targets = await this.getAllTargets();
    const totalDiscovered = this.knownUrlSet.size;

    const stats = {
      totalTargets: targets.length,
      pendingTargets: targets.filter(t => t.status === 'pending').length,
      crawledTargets: targets.filter(t => t.status === 'completed').length,
      failedTargets: targets.filter(t => t.status === 'failed').length,
      totalDiscovered: totalDiscovered
    };

    return stats;
  }

  async clearAll() {
    await this.init();
    this.knownUrlSet.clear();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(['targets', 'discovered_urls'], 'readwrite');
      tx.objectStore('targets').clear();
      tx.objectStore('discovered_urls').clear();

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
