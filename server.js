/**
 * Crawlizer Local Server
 * Cyberpunk Deep Web Recon, Secret Spider & Supply Chain Audit Server
 * Runs locally on http://localhost:4488
 */

const express = require('express');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const path = require('path');
const fs = require('fs');

const PORT = parseInt(process.env.PORT, 10) || 4488;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, '.data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ============================================================================
// PERSISTENT DATA MANAGER
// ============================================================================

class LocalDataManager {
  constructor() {
    this.targetsFile = path.join(DATA_DIR, 'targets.json');
    this.urlsFile = path.join(DATA_DIR, 'urls.json');
    this.secretsFile = path.join(DATA_DIR, 'secrets.json');
    this.supplyChainFile = path.join(DATA_DIR, 'supply_chain.json');
    this.logsFile = path.join(DATA_DIR, 'logs.json');

    this.targets = this.loadJson(this.targetsFile, []);
    this.urls = this.loadJson(this.urlsFile, []);
    this.secrets = this.loadJson(this.secretsFile, []);
    this.supplyChain = this.loadJson(this.supplyChainFile, []);
    this.logs = this.loadJson(this.logsFile, []);

    // In-memory deduplication lookup sets/maps
    this.urlSet = new Set(this.urls.map(u => this.normalizeUrl(u.url)));
    this.secretMap = new Map();
    this.secrets.forEach(s => {
      const key = `${s.ruleName}:${s.match}`;
      this.secretMap.set(key, s);
    });

    this.supplyMap = new Map();
    this.supplyChain.forEach(p => {
      const key = `${p.ecosystem || 'npm'}:${p.name}`;
      this.supplyMap.set(key, p);
    });

    this.saveDebounceTimer = null;
  }

  loadJson(filePath, defaultValue) {
    try {
      if (fs.existsSync(filePath)) {
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
      }
    } catch (e) {
      console.warn(`[Storage] Failed to read ${filePath}, using default.`, e.message);
    }
    return defaultValue;
  }

  scheduleSave() {
    if (this.saveDebounceTimer) return;
    this.saveDebounceTimer = setTimeout(() => {
      this.saveDebounceTimer = null;
      this.persistToDisk();
    }, 400);
  }

  async persistToDisk() {
    try {
      await Promise.all([
        fs.promises.writeFile(this.targetsFile, JSON.stringify(this.targets, null, 2)),
        fs.promises.writeFile(this.urlsFile, JSON.stringify(this.urls, null, 2)),
        fs.promises.writeFile(this.secretsFile, JSON.stringify(this.secrets, null, 2)),
        fs.promises.writeFile(this.supplyChainFile, JSON.stringify(this.supplyChain, null, 2)),
        fs.promises.writeFile(this.logsFile, JSON.stringify(this.logs.slice(-500), null, 2))
      ]);
    } catch (err) {
      console.error('[Storage] Error saving data to disk:', err.message);
    }
  }

  normalizeUrl(raw) {
    if (!raw) return '';
    try {
      const u = new URL(raw);
      return (u.origin + u.pathname + (u.search ? u.search : '')).replace(/\/+$/, '').toLowerCase();
    } catch {
      return String(raw).trim().toLowerCase();
    }
  }

  // --- Targets ---
  getTargets() {
    return this.targets;
  }

  addTarget(targetUrl) {
    const trimmed = String(targetUrl).trim();
    if (!trimmed) return null;
    const exists = this.targets.find(t => t.url.toLowerCase() === trimmed.toLowerCase());
    if (exists) return exists;

    const record = {
      id: Date.now() + Math.random().toString(36).substring(2, 7),
      url: trimmed,
      status: 'pending',
      addedAt: new Date().toISOString()
    };
    this.targets.push(record);
    this.scheduleSave();
    return record;
  }

  clearTargets() {
    this.targets = [];
    this.scheduleSave();
  }

  // --- URLs ---
  getUrls(filter = {}) {
    let list = this.urls;
    if (filter.type && filter.type !== 'all') {
      list = list.filter(u => u.type === filter.type);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      list = list.filter(u => (u.url && u.url.toLowerCase().includes(q)) || (u.sourceUrl && u.sourceUrl.toLowerCase().includes(q)));
    }
    return list;
  }

  addUrls(urlItems = []) {
    const added = [];
    urlItems.forEach(item => {
      if (!item || !item.url) return;
      const normalized = this.normalizeUrl(item.url);
      if (this.urlSet.has(normalized)) return;

      this.urlSet.add(normalized);
      const record = {
        id: this.urls.length + 1,
        url: item.url,
        type: item.type || 'href',
        scope: item.scope || 'in-scope',
        sourceUrl: item.sourceUrl || '',
        status: item.status || null,
        method: item.method || 'GET',
        discoveredAt: item.discoveredAt || new Date().toISOString()
      };
      this.urls.push(record);
      added.push(record);
    });

    if (added.length > 0) {
      this.scheduleSave();
    }
    return added;
  }

  // --- Secrets ---
  getSecrets(filter = {}) {
    let list = this.secrets;
    if (filter.severity && filter.severity !== 'all') {
      list = list.filter(s => s.severity === filter.severity);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      list = list.filter(s =>
        (s.ruleName && s.ruleName.toLowerCase().includes(q)) ||
        (s.match && s.match.toLowerCase().includes(q)) ||
        (s.sourceUrl && s.sourceUrl.toLowerCase().includes(q))
      );
    }
    return list;
  }

  addSecrets(secretItems = []) {
    const updated = [];
    secretItems.forEach(item => {
      if (!item || !item.match || !item.ruleName) return;
      const key = `${item.ruleName}:${item.match}`;
      const existing = this.secretMap.get(key);

      const src = {
        url: item.sourceUrl || item.url || '',
        type: item.sourceType || 'html',
        context: item.context || ''
      };

      if (existing) {
        if (!existing.sources) existing.sources = [];
        const hasSrc = existing.sources.some(s => s.url === src.url && s.context === src.context);
        if (!hasSrc && src.url) {
          existing.sources.push(src);
        }
        existing.lastDiscoveredAt = new Date().toISOString();
        updated.push(existing);
      } else {
        const record = {
          id: this.secrets.length + 1,
          ruleName: item.ruleName,
          severity: item.severity || 'high',
          category: item.category || 'General',
          match: item.match,
          masked: item.masked || '••••••••',
          sourceUrl: src.url,
          sourceType: src.type,
          context: src.context,
          sources: src.url ? [src] : [],
          discoveredAt: new Date().toISOString(),
          lastDiscoveredAt: new Date().toISOString()
        };
        this.secretMap.set(key, record);
        this.secrets.push(record);
        updated.push(record);
      }
    });

    if (updated.length > 0) {
      this.scheduleSave();
    }
    return updated;
  }

  // --- Supply Chain ---
  getSupplyChain(filter = {}) {
    let list = this.supplyChain;
    if (filter.ecosystem && filter.ecosystem !== 'all') {
      list = list.filter(p => (p.ecosystem || 'npm').toLowerCase() === filter.ecosystem.toLowerCase());
    }
    if (filter.severity && filter.severity !== 'all') {
      list = list.filter(p => (p.riskLevel || 'LOW').toLowerCase() === filter.severity.toLowerCase());
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      list = list.filter(p =>
        (p.name && p.name.toLowerCase().includes(q)) ||
        (p.version && p.version.toLowerCase().includes(q))
      );
    }
    return list;
  }

  addSupplyChain(findings = []) {
    const updated = [];
    findings.forEach(f => {
      if (!f || !f.name) return;
      const key = `${f.ecosystem || 'npm'}:${f.name}`;
      const existing = this.supplyMap.get(key);

      const srcList = Array.isArray(f.sources) ? f.sources : (f.sourceUrl ? [{ url: f.sourceUrl, type: f.sourceType || 'code', context: f.context || '' }] : []);

      if (existing) {
        if (!existing.sources) existing.sources = [];
        srcList.forEach(s => {
          if (!existing.sources.some(es => es.url === s.url && es.context === s.context)) {
            existing.sources.push(s);
          }
        });
        if (f.advisories && f.advisories.length > 0) {
          existing.advisories = f.advisories;
          existing.advisoriesCount = f.advisories.length;
        }
        if (f.riskLevel) existing.riskLevel = f.riskLevel;
        existing.lastUpdated = new Date().toISOString();
        updated.push(existing);
      } else {
        const record = {
          id: this.supplyChain.length + 1,
          type: f.type || 'package',
          name: f.name,
          version: f.version || '',
          ecosystem: f.ecosystem || 'npm',
          riskLevel: f.riskLevel || 'LOW',
          isUnregistered: Boolean(f.isUnregistered),
          weeklyDownloads: f.weeklyDownloads ?? null,
          advisories: f.advisories || [],
          advisoriesCount: (f.advisories || []).length,
          sources: srcList,
          context: f.context || '',
          discoveredAt: new Date().toISOString(),
          lastUpdated: new Date().toISOString()
        };
        this.supplyMap.set(key, record);
        this.supplyChain.push(record);
        updated.push(record);
      }
    });

    if (updated.length > 0) {
      this.scheduleSave();
    }
    return updated;
  }

  // --- Logs ---
  getLogs(limit = 200) {
    return this.logs.slice(-limit);
  }

  addLog(level, message, detail = null) {
    const logItem = {
      id: Date.now() + Math.random().toString(36).substring(2, 6),
      time: new Date().toLocaleTimeString(),
      timestamp: Date.now(),
      level: level || 'inf',
      message: String(message),
      detail
    };
    this.logs.push(logItem);
    if (this.logs.length > 1000) this.logs.shift();
    this.scheduleSave();
    return logItem;
  }

  clearLogs() {
    this.logs = [];
    this.scheduleSave();
  }

  // --- Wipe ---
  wipeAll() {
    this.targets = [];
    this.urls = [];
    this.secrets = [];
    this.supplyChain = [];
    this.logs = [];
    this.urlSet.clear();
    this.secretMap.clear();
    this.supplyMap.clear();
    this.persistToDisk();
  }

  getMetrics() {
    const totalUrls = this.urls.length;
    const internalUrls = this.urls.filter(u => u.scope === 'in-scope').length;
    const externalUrls = totalUrls - internalUrls;

    const totalSecrets = this.secrets.length;
    const criticalSecrets = this.secrets.filter(s => s.severity === 'critical').length;
    const highSecrets = this.secrets.filter(s => s.severity === 'high').length;
    const mediumSecrets = this.secrets.filter(s => s.severity === 'medium').length;

    const totalSupply = this.supplyChain.length;
    const unregSupply = this.supplyChain.filter(p => p.isUnregistered).length;
    const vulnSupply = this.supplyChain.filter(p => p.advisoriesCount > 0).length;

    return {
      targetsCount: this.targets.length,
      urls: {
        total: totalUrls,
        inScope: internalUrls,
        outOfScope: externalUrls,
        jsBundles: this.urls.filter(u => u.type === 'script' || (u.url && u.url.includes('.js'))).length
      },
      secrets: {
        total: totalSecrets,
        critical: criticalSecrets,
        high: highSecrets,
        medium: mediumSecrets
      },
      supplyChain: {
        total: totalSupply,
        unregistered: unregSupply,
        vulnerabilities: vulnSupply
      }
    };
  }
}

const db = new LocalDataManager();

// ============================================================================
// CRAWL ORCHESTRATOR & AGENT MANAGER
// ============================================================================

class CrawlOrchestrator {
  constructor() {
    this.state = 'idle'; // 'idle' | 'running' | 'paused'
    this.agentSocket = null;
    this.uiSockets = new Set();
    this.pendingQueue = [];
    this.visitedUrls = new Set();
    this.currentJob = null;
    this.agentInfo = { connected: false, version: null, lastSeen: null };
  }

  setAgentSocket(ws, info = {}) {
    this.agentSocket = ws;
    this.agentInfo = {
      connected: true,
      version: info.version || '1.0.5',
      name: info.name || 'Chrome Extension Agent',
      lastSeen: Date.now()
    };
    db.addLog('inf', `[Agent] Connected: ${this.agentInfo.name} v${this.agentInfo.version}`);
    this.broadcastToUI({ type: 'agent:status', ...this.agentInfo });

    // If crawl is currently running and waiting for job, dispatch
    if (this.state === 'running' && !this.currentJob) {
      this.dispatchNext();
    }
  }

  removeAgentSocket(ws) {
    if (this.agentSocket === ws) {
      this.agentSocket = null;
      this.agentInfo.connected = false;
      this.currentJob = null;
      db.addLog('wrn', '[Agent] Disconnected. Standing by for reconnection...');
      this.broadcastToUI({ type: 'agent:status', connected: false });
    }
  }

  addUISocket(ws) {
    this.uiSockets.add(ws);
    // Send initial status
    ws.send(JSON.stringify({
      type: 'init:state',
      agent: this.agentInfo,
      crawlState: this.state,
      metrics: db.getMetrics(),
      currentJob: this.currentJob
    }));
  }

  removeUISocket(ws) {
    this.uiSockets.delete(ws);
  }

  broadcastToUI(msg) {
    const payload = JSON.stringify(msg);
    this.uiSockets.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      }
    });
  }

  startCrawl() {
    if (this.state === 'running') return;

    this.state = 'running';
    db.addLog('inf', '[Crawler] Crawl session initiated.');

    // Populate queue with pending seed targets if queue is empty
    if (this.pendingQueue.length === 0) {
      const targets = db.getTargets();
      targets.forEach(t => {
        if (!this.visitedUrls.has(t.url)) {
          this.pendingQueue.push(t.url);
        }
      });
    }

    if (this.pendingQueue.length === 0) {
      db.addLog('wrn', '[Crawler] Target queue is empty. Add targets to begin crawling!');
    }

    this.broadcastToUI({ type: 'crawl:state', state: this.state, queueCount: this.pendingQueue.length });
    this.dispatchNext();
  }

  pauseCrawl() {
    this.state = 'paused';
    db.addLog('wrn', '[Crawler] Crawl session paused.');
    this.broadcastToUI({ type: 'crawl:state', state: this.state });
  }

  resumeCrawl() {
    if (this.state !== 'paused') return;
    this.state = 'running';
    db.addLog('inf', '[Crawler] Crawl session resumed.');
    this.broadcastToUI({ type: 'crawl:state', state: this.state });
    this.dispatchNext();
  }

  stopCrawl() {
    this.state = 'idle';
    this.currentJob = null;
    this.pendingQueue = [];
    if (this.agentSocket && this.agentSocket.readyState === WebSocket.OPEN) {
      this.agentSocket.send(JSON.stringify({ type: 'crawl:stop' }));
    }
    db.addLog('inf', '[Crawler] Crawl session stopped.');
    this.broadcastToUI({ type: 'crawl:state', state: this.state, queueCount: 0 });
  }

  triggerActiveTabAudit() {
    if (!this.agentSocket || this.agentSocket.readyState !== WebSocket.OPEN) {
      db.addLog('err', '[Audit] No Chrome Extension Agent connected to audit active tab.');
      return false;
    }
    this.agentSocket.send(JSON.stringify({ type: 'crawl:active_tab' }));
    db.addLog('inf', '[Audit] Dispatched active tab inspection request to Chrome Agent.');
    return true;
  }

  dispatchNext() {
    if (this.state !== 'running') return;
    if (this.currentJob) return;

    if (!this.agentSocket || this.agentSocket.readyState !== WebSocket.OPEN) {
      db.addLog('wrn', '[Crawler] Waiting for Chrome Extension agent to connect before scanning...');
      return;
    }

    if (this.pendingQueue.length === 0) {
      this.state = 'idle';
      db.addLog('inf', '[Crawler] Queue completed. All seed targets and in-scope links processed.');
      this.broadcastToUI({ type: 'crawl:state', state: this.state, queueCount: 0 });
      return;
    }

    const nextUrl = this.pendingQueue.shift();
    this.visitedUrls.add(nextUrl);
    this.currentJob = { url: nextUrl, startedAt: Date.now() };

    db.addLog('inf', `[Browser] Instructing Agent to open and scan tab: ${nextUrl}`);
    this.broadcastToUI({
      type: 'crawl:job_started',
      url: nextUrl,
      queueCount: this.pendingQueue.length
    });

    this.agentSocket.send(JSON.stringify({
      type: 'crawl:job',
      url: nextUrl
    }));
  }

  handleJobCompleted(url, findings = {}) {
    this.currentJob = null;

    let addedUrlsCount = 0;
    let addedSecretsCount = 0;
    let addedSupplyCount = 0;

    // Process & store extracted URLs
    if (findings.urls && Array.isArray(findings.urls)) {
      const added = db.addUrls(findings.urls);
      addedUrlsCount = added.length;
      if (added.length > 0) {
        this.broadcastToUI({ type: 'data:urls', items: added });
      }

      // If deep crawl allowed, add newly found in-scope URLs to queue
      added.forEach(u => {
        if (u.scope === 'in-scope' && !this.visitedUrls.has(u.url) && !this.pendingQueue.includes(u.url)) {
          this.pendingQueue.push(u.url);
        }
      });
    }

    // Process & store extracted Secrets
    if (findings.secrets && Array.isArray(findings.secrets)) {
      const added = db.addSecrets(findings.secrets);
      addedSecretsCount = added.length;
      if (added.length > 0) {
        this.broadcastToUI({ type: 'data:secrets', items: added });
      }
    }

    // Process & store extracted Supply Chain packages
    if (findings.supplyChain && Array.isArray(findings.supplyChain)) {
      const added = db.addSupplyChain(findings.supplyChain);
      addedSupplyCount = added.length;
      if (added.length > 0) {
        this.broadcastToUI({ type: 'data:supply', items: added });
      }
    }

    db.addLog('inf', `[Scanned] Finished ${url} -> ${addedUrlsCount} new endpoints, ${addedSecretsCount} secrets, ${addedSupplyCount} packages.`);

    this.broadcastToUI({
      type: 'crawl:job_finished',
      url,
      queueCount: this.pendingQueue.length,
      metrics: db.getMetrics()
    });

    // Dispatch next URL in queue
    setTimeout(() => this.dispatchNext(), 250);
  }
}

const orchestrator = new CrawlOrchestrator();

// ============================================================================
// EXPRESS HTTP APP & STATIC ASSETS
// ============================================================================

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// CORS headers to enable seamless interaction from extension & dashboards
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Explicit root route serves dashboard.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Serve all static files from repository directory
app.use(express.static(__dirname));

// ============================================================================
// REST API ROUTES
// ============================================================================

app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    port: PORT,
    version: '1.0.5',
    agent: orchestrator.agentInfo,
    crawler: {
      state: orchestrator.state,
      queueCount: orchestrator.pendingQueue.length,
      currentJob: orchestrator.currentJob
    },
    metrics: db.getMetrics()
  });
});

app.get('/api/metrics', (req, res) => {
  res.json(db.getMetrics());
});

// Targets
app.get('/api/targets', (req, res) => {
  res.json(db.getTargets());
});

app.post('/api/targets', (req, res) => {
  const { url, urls } = req.body;
  const added = [];
  if (url) {
    const item = db.addTarget(url);
    if (item) added.push(item);
  }
  if (Array.isArray(urls)) {
    urls.forEach(u => {
      const item = db.addTarget(u);
      if (item) added.push(item);
    });
  }
  res.json({ success: true, added, targets: db.getTargets() });
});

app.delete('/api/targets', (req, res) => {
  db.clearTargets();
  res.json({ success: true });
});

// URLs
app.get('/api/urls', (req, res) => {
  const filter = {
    type: req.query.type,
    search: req.query.search
  };
  res.json(db.getUrls(filter));
});

app.post('/api/urls', (req, res) => {
  const items = Array.isArray(req.body) ? req.body : (req.body.items || [req.body]);
  const added = db.addUrls(items);
  if (added.length > 0) {
    orchestrator.broadcastToUI({ type: 'data:urls', items: added, metrics: db.getMetrics() });
  }
  res.json({ success: true, count: added.length });
});

// Secrets
app.get('/api/secrets', (req, res) => {
  const filter = {
    severity: req.query.severity,
    search: req.query.search
  };
  res.json(db.getSecrets(filter));
});

app.post('/api/secrets', (req, res) => {
  const items = Array.isArray(req.body) ? req.body : (req.body.items || [req.body]);
  const added = db.addSecrets(items);
  if (added.length > 0) {
    orchestrator.broadcastToUI({ type: 'data:secrets', items: added, metrics: db.getMetrics() });
  }
  res.json({ success: true, count: added.length });
});

app.delete('/api/secrets', (req, res) => {
  db.secrets = [];
  db.secretMap.clear();
  db.scheduleSave();
  res.json({ success: true });
});

// Supply Chain
app.get('/api/supply-chain', (req, res) => {
  const filter = {
    ecosystem: req.query.ecosystem,
    severity: req.query.severity,
    search: req.query.search
  };
  res.json(db.getSupplyChain(filter));
});

app.post('/api/supply-chain', (req, res) => {
  const items = Array.isArray(req.body) ? req.body : (req.body.items || [req.body]);
  const added = db.addSupplyChain(items);
  if (added.length > 0) {
    orchestrator.broadcastToUI({ type: 'data:supply', items: added, metrics: db.getMetrics() });
  }
  res.json({ success: true, count: added.length });
});

app.delete('/api/supply-chain', (req, res) => {
  db.supplyChain = [];
  db.supplyMap.clear();
  db.scheduleSave();
  res.json({ success: true });
});

// Logs
app.get('/api/logs', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 200;
  res.json(db.getLogs(limit));
});

app.post('/api/logs', (req, res) => {
  const { level, message, detail } = req.body;
  const logItem = db.addLog(level, message, detail);
  orchestrator.broadcastToUI({ type: 'log:new', item: logItem });
  res.json({ success: true, item: logItem });
});

app.delete('/api/logs', (req, res) => {
  db.clearLogs();
  res.json({ success: true });
});

// Crawl Controls
app.post('/api/crawl/start', (req, res) => {
  orchestrator.startCrawl();
  res.json({ success: true, state: orchestrator.state });
});

app.post('/api/crawl/pause', (req, res) => {
  orchestrator.pauseCrawl();
  res.json({ success: true, state: orchestrator.state });
});

app.post('/api/crawl/resume', (req, res) => {
  orchestrator.resumeCrawl();
  res.json({ success: true, state: orchestrator.state });
});

app.post('/api/crawl/stop', (req, res) => {
  orchestrator.stopCrawl();
  res.json({ success: true, state: orchestrator.state });
});

app.post('/api/crawl/active-tab', (req, res) => {
  const dispatched = orchestrator.triggerActiveTabAudit();
  res.json({ success: dispatched });
});

app.post('/api/wipe', (req, res) => {
  orchestrator.stopCrawl();
  db.wipeAll();
  orchestrator.broadcastToUI({ type: 'data:wipe', metrics: db.getMetrics() });
  db.addLog('wrn', '[Database] Wipe completed. All endpoints, secrets, and supply chain records cleared.');
  res.json({ success: true });
});

// ============================================================================
// WEBSOCKET SERVER & REALTIME COMMS
// ============================================================================

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  let clientRole = 'ui'; // default is dashboard UI

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      // Chrome Extension Agent Registration
      if (msg.type === 'register:agent') {
        clientRole = 'agent';
        orchestrator.setAgentSocket(ws, {
          name: msg.client || 'Chrome Extension',
          version: msg.version || '1.0.5'
        });
        return;
      }

      // Chrome Agent Findings from Scanned Tab
      if (msg.type === 'agent:findings') {
        orchestrator.handleJobCompleted(msg.targetUrl, {
          urls: msg.urls || [],
          secrets: msg.secrets || [],
          supplyChain: msg.supplyChain || []
        });
        return;
      }

      // Chrome Agent Log Forwarding
      if (msg.type === 'agent:log') {
        const item = db.addLog(msg.level || 'inf', `[Agent] ${msg.message}`);
        orchestrator.broadcastToUI({ type: 'log:new', item });
        return;
      }

      // UI Commands
      if (msg.type === 'ui:crawl_start') orchestrator.startCrawl();
      if (msg.type === 'ui:crawl_pause') orchestrator.pauseCrawl();
      if (msg.type === 'ui:crawl_resume') orchestrator.resumeCrawl();
      if (msg.type === 'ui:crawl_stop') orchestrator.stopCrawl();
      if (msg.type === 'ui:active_tab') orchestrator.triggerActiveTabAudit();
      if (msg.type === 'ui:log') {
        const item = db.addLog(msg.level || 'inf', msg.message);
        orchestrator.broadcastToUI({ type: 'log:new', item });
      }

    } catch (e) {
      console.warn('[WS] Error processing message:', e.message);
    }
  });

  ws.on('close', () => {
    if (clientRole === 'agent') {
      orchestrator.removeAgentSocket(ws);
    } else {
      orchestrator.removeUISocket(ws);
    }
  });

  // Default register as UI client until identified otherwise
  orchestrator.addUISocket(ws);
});

// ============================================================================
// SERVER INITIALIZATION
// ============================================================================

server.listen(PORT, HOST, () => {
  const line = '━'.repeat(64);
  console.log(`\n${line}`);
  console.log(`⚡ CRAWLIZER LOCAL SERVER v1.0.5`);
  console.log(`   Cyberpunk Web Recon, Secret Spider & Supply Chain Audit`);
  console.log(`${line}`);
  console.log(`📡 Dashboard UI  : http://localhost:${PORT}`);
  console.log(`🔌 WebSocket API : ws://localhost:${PORT}/ws`);
  console.log(`💾 Persistent DB : ${DATA_DIR}`);
  console.log(`🤖 Agent Status  : Waiting for Chrome Extension connection...`);
  console.log(`${line}\n`);
});
