/**
 * Crawlizer & Supply Chain Security Scanner - Background Service Worker
 * Combines advanced web crawling / dashboard lifecycle management
 * with multi-ecosystem package registry queries, OSV.dev CVE advisories,
 * dependency confusion heuristics, and badge notifications.
 */

try {
  importScripts('secret-scanner.js', 'supply-chain-scanner.js');
} catch (e) {
  console.warn('importScripts failed:', e);
}

// ============================================================================
// UTILITIES
// ============================================================================

class LRUCache {
  constructor(maxSize) {
    this.maxSize = Math.max(1, Number(maxSize) || 32);
    this.map = new Map();
  }

  get(key) {
    if (!this.map.has(key)) return undefined;
    // Re-insert to mark as recently used.
    const value = this.map.get(key);
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);
    while (this.map.size > this.maxSize) {
      const oldestKey = this.map.keys().next().value;
      this.map.delete(oldestKey);
    }
  }

  has(key) {
    return this.map.has(key);
  }

  delete(key) {
    this.map.delete(key);
  }

  get size() {
    return this.map.size;
  }

  clear() {
    this.map.clear();
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================

const NETWORK_TIMEOUT_MS = 8000;
const OSV_TIMEOUT_MS = 3000;

const OSV_ECOSYSTEM_MAP = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  rubygems: 'RubyGems',
  nuget: 'NuGet',
  composer: 'Packagist',
  golang: 'Go',
  crates: 'crates.io'
};

const RISK_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const bumpRisk = (current, next) => (RISK_RANK[next] > RISK_RANK[current] ? next : current);

// Severity classification bands used to rank OSV advisories (CVSS-equivalent).
const ADVISORY_SEVERITY_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

class BackgroundState {
  constructor() {
    // Bounded LRU instead of unbounded Map to prevent memory leaks under heavy tab churn.
    this.tabResults = new LRUCache(32);
    this.scanTimestamps = new LRUCache(64);
  }

  setTabResult(tabId, result) {
    this.tabResults.set(tabId, { ...result, timestamp: Date.now() });
  }

  getTabResult(tabId) {
    return this.tabResults.get(tabId);
  }

  removeTab(tabId) {
    this.tabResults.delete(tabId);
    this.scanTimestamps.delete(tabId);
  }

  canScan(tabId) {
    const lastScan = this.scanTimestamps.get(tabId);
    if (!lastScan) return true;
    return Date.now() - lastScan > 5000;
  }

  recordScan(tabId) {
    this.scanTimestamps.set(tabId, Date.now());
  }

  cleanup() {
    // LRU evicts automatically; periodic flush to drop stale poisoned entries.
    const now = Date.now();
    const maxAge = 10 * 60 * 1000;
    for (const [key, value] of this.tabResults.map.entries()) {
      if (value && now - value.timestamp > maxAge) {
        this.tabResults.delete(key);
      }
    }
  }
}

const state = new BackgroundState();

// ============================================================================
// BADGE MANAGEMENT (Icon badge numbers disabled)
// ============================================================================

class BadgeManager {
  static async updateBadge(tabId, riskCount) {
    // Disabled: No badge text or numbers on icon
  }

  static async clearBadge(tabId) {
    try {
      if (typeof chrome !== 'undefined' && chrome.action && chrome.action.setBadgeText) {
        await chrome.action.setBadgeText({ text: '', tabId });
      }
    } catch (error) {
      // ignore
    }
  }
}

// ============================================================================
// OSV ADVISORY LOOKUP
// ============================================================================

class OsvChecker {
  // Per-process LRU; OSV responses are valid for 24h in practice but invalidating
  // on tab close keeps memory bounded.
  static cache = new LRUCache(256);

  static ecosystemFor(internalName) {
    return OSV_ECOSYSTEM_MAP[String(internalName || '').toLowerCase()] || null;
  }

  static getCacheKey(ecosystem, name, version) {
    return `${ecosystem}:${name}:${version || ''}`;
  }

  static async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeoutMs || NETWORK_TIMEOUT_MS);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Look up advisories for one (ecosystem, name, optional version).
   * Returns { advisories: [...], osvError: string|undefined }.
   * Never throws.
   */
  static async lookup(ecosystem, name, version) {
    const osvEco = this.ecosystemFor(ecosystem);
    if (!osvEco || !name) return { advisories: [] };

    const cacheKey = this.getCacheKey(osvEco, name, version);
    const cached = this.cache.get(cacheKey);
    if (cached !== undefined) return cached;

    const body = { package: { name, ecosystem: osvEco } };
    if (version) body.version = String(version);

    try {
      const res = await this.fetchWithTimeout('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        timeoutMs: OSV_TIMEOUT_MS
      });

      if (!res.ok) {
        const result = { advisories: [], osvError: `OSV HTTP ${res.status}` };
        return result;
      }

      const data = await res.json();
      const advisories = this.parseAdvisories(data.vulns || []);

      // Cache only successful lookups to avoid poisoning the cache on transient errors.
      this.cache.set(cacheKey, { advisories });
      return { advisories };
    } catch (e) {
      // Timeouts / network errors should NOT poison cache — fall through to empty.
      return { advisories: [], osvError: e.name === 'AbortError' ? 'OSV timeout' : 'OSV unreachable' };
    }
  }

  static parseAdvisories(vulns) {
    const advisories = [];
    for (const v of vulns) {
      if (!v || !v.id) continue;
      const severity = this.pickSeverity(v);
      const aliases = Array.isArray(v.aliases) ? v.aliases.map(String) : [];
      const cveAlias = aliases.find(a => a.startsWith('CVE-')) || null;
      advisories.push({
        id: String(v.id),
        cveId: cveAlias || String(v.id),
        summary: String(v.summary || v.details || '').slice(0, 240),
        severity,
        aliases,
        published: v.published || null,
        modified: v.modified || null
      });
    }
    // Highest severity first.
    advisories.sort((a, b) => (ADVISORY_SEVERITY_RANK[b.severity] || 0) - (ADVISORY_SEVERITY_RANK[a.severity] || 0));
    return advisories;
  }

  static pickSeverity(v) {
    // OSV.dev may attach CVSS_V3 score strings in v.severity[].score.
    // Some advisories only expose "database_specific" severities. Default to MEDIUM if unknown but present.
    const sev = Array.isArray(v.severity) ? v.severity : [];

    for (const entry of sev) {
      const type = String(entry.type || '').toUpperCase();
      const score = Number(entry.score);
      if (type === 'CVSS_V3' && Number.isFinite(score)) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
      }
    }

    const db = v.database_specific && v.database_specific.severity;
    if (typeof db === 'string') {
      const upper = db.toUpperCase();
      if (upper === 'MODERATE') return 'MEDIUM';
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper)) return upper;
    }

    // GHSA-issued advisories without numeric severity default to HIGH.
    if (typeof v.id === 'string' && v.id.startsWith('GHSA-')) return 'HIGH';
    return 'MEDIUM';
  }
}

// ============================================================================
// NPM RISK HEURISTICS
// ============================================================================

class NpmRiskHeuristics {
  static MIN_DOWNLOADS_SUSPICIOUS = 100;
  static MIN_MAINTAINERS_HEALTHY = 2;
  static ABANDONED_YEARS = 2;

  // Allowlist of legitimate versioned/confusable package names.
  static KNOWN_VERSIONED_NAMES = new Set([
    'vue2', 'vue3',
    'react16', 'react17', 'react18', 'react19',
    'webpack4', 'webpack5',
    'typescript3', 'typescript4', 'typescript5',
    'auth0', 'auth-0',
    'level0', 'level-0',
    'saas0', 'saas1', 'saas10',
    'lerna2', 'lerna3', 'lerna4',
    'ionic1', 'ionic3', 'ionic4', 'ionic5',
    'node12', 'node14', 'node16', 'node18', 'node20', 'node22',
    'es5', 'es6', 'es7', 'es2015', 'es2017', 'es2020', 'es2021', 'es2022',
    'log10', 'log0', '10print', '10x', '100', '0x',
    'graphql0', 'apollo1', 'apollo2',
    'svelte3', 'svelte4', 'svelte5',
    'next0', 'next1', 'next2', 'next3', 'next4', 'next5',
    'nuxt2', 'nuxt3',
    'nest5', 'nest6', 'nest7', 'nest8', 'nest9', 'nest10',
    'pdfkit0', 'pdfjs1', 'pdfjs2', 'pdfjs3', 'pdfjs4'
  ]);

  static assess(info, downloads) {
    const reasons = [];
    let level = 'LOW';
    let suspicious = false;

    // 1. Dependency-confusion signature: registered but no public downloads + no repo
    if (downloads < this.MIN_DOWNLOADS_SUSPICIOUS && !info.repository && !info.homepage) {
      suspicious = true;
      level = bumpRisk(level, 'HIGH');
      reasons.push('Low downloads + No repository');
    }

    // 2. Single-maintainer + no repo
    const maintainers = Array.isArray(info.maintainers) ? info.maintainers.length : 0;
    if (maintainers > 0 && maintainers < this.MIN_MAINTAINERS_HEALTHY && !info.repository) {
      suspicious = true;
      level = bumpRisk(level, 'MEDIUM');
      reasons.push(`Solo maintainer (${maintainers}) without repo link`);
    }

    // 3. Abandoned: no release in >= 2 years
    if (info.time && info.time.modified) {
      const modifiedMs = Date.parse(info.time.modified);
      if (Number.isFinite(modifiedMs)) {
        const yearsStale = (Date.now() - modifiedMs) / (365 * 24 * 60 * 60 * 1000);
        if (yearsStale >= this.ABANDONED_YEARS) {
          level = bumpRisk(level, maintainers === 1 ? 'MEDIUM' : 'LOW');
          reasons.push(`Not updated in ${yearsStale.toFixed(1)} years`);
        }
      }
    }

    // 4. New package (created < 90 days) with very few downloads -> likely typosquat
    if (info.time && info.time.created) {
      const createdMs = Date.parse(info.time.created);
      if (Number.isFinite(createdMs)) {
        const ageDays = (Date.now() - createdMs) / (1000 * 60 * 60 * 24);
        if (ageDays < 90 && downloads < this.MIN_DOWNLOADS_SUSPICIOUS * 5) {
          suspicious = true;
          level = bumpRisk(level, 'MEDIUM');
          reasons.push(`New package (${Math.round(ageDays)} days) with low adoption`);
        }
      }
    }

    // 5. Typosquat-like patterns
    const nameForHeuristics = String(info.name || '');
    const isKnownVersioned = NpmRiskHeuristics.KNOWN_VERSIONED_NAMES.has(nameForHeuristics);
    const hasLongNumber = /[0-9]{4,}/.test(nameForHeuristics);
    const hasDigitConfusable = /(?:l0|10|i0|1o|0l|0i|o0|0o)/.test(nameForHeuristics);
    if (!isKnownVersioned && (hasLongNumber || hasDigitConfusable)) {
      suspicious = true;
      level = bumpRisk(level, 'MEDIUM');
      reasons.push('Suspicious name pattern');
    }

    return { suspicious, riskLevel: level, riskReasons: reasons };
  }

  /**
   * Risk adjustment from OSV advisories. Any CVE bumps to HIGH; CVSS>=7 bumps to CRITICAL.
   */
  static applyAdvisoryRisk(existingLevel, advisories) {
    if (!advisories || advisories.length === 0) return existingLevel;
    let next = existingLevel;
    for (const adv of advisories) {
      if (adv.severity === 'CRITICAL') next = bumpRisk(next, 'CRITICAL');
      else if (adv.severity === 'HIGH') next = bumpRisk(next, 'HIGH');
      else next = bumpRisk(next, 'MEDIUM');
    }
    return next;
  }
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

class MessageHandler {
  static async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeoutMs || NETWORK_TIMEOUT_MS);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  static async handleNotifyRisks(request, sender) {
    if (!sender.tab?.id) {
      return { success: false, error: 'No tab ID' };
    }

    const tabId = sender.tab.id;
    const { suspiciousPackages = [], exposedFiles = [], advisoriesSummary = null } = request;

    state.setTabResult(tabId, { suspiciousPackages, exposedFiles, advisoriesSummary });

    const totalRisks = suspiciousPackages.length + exposedFiles.length;
    await BadgeManager.updateBadge(tabId, totalRisks);

    return { success: true, totalRisks };
  }

  static async handleGetResults(request) {
    const { tabId } = request;
    const result = state.getTabResult(tabId);
    return result || { packages: [], exposedFiles: [], advisoriesSummary: null };
  }

  static async handleCanScan(request) {
    return { canScan: state.canScan(request.tabId) };
  }

  static async handleRecordScan(request) {
    state.recordScan(request.tabId);
    return { success: true };
  }

  static async handleGetSettings() {
    try {
      const settings = await chrome.storage.sync.get({
        autoScan: true,
        deepCrawl: true,
        osvLookup: true,
        showAllRisks: false
      });
      return settings;
    } catch (error) {
      console.error('Failed to get settings:', error);
      return { autoScan: true, deepCrawl: true, osvLookup: true, showAllRisks: false };
    }
  }

  static async handleSaveSettings(request) {
    try {
      const { settings } = request;
      await chrome.storage.sync.set(settings);
      if (settings.autoScan === false) {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) await BadgeManager.clearBadge(tab.id);
      }
      return { success: true };
    } catch (error) {
      console.error('Failed to save settings:', error);
      return { success: false, error: error.message };
    }
  }

  static async handleAnalyzePackage(request) {
    const { name, sources, ecosystem = 'npm', version, options = {} } = request;
    try {
      if (ecosystem === 'npm') {
        return await MessageHandler.analyzeNpm(name, sources, version, options);
      }
      return await MessageHandler.analyzeGeneric(ecosystem, name, sources, options);
    } catch (e) {
      return { name, ecosystem, error: e.message, sources, advisories: [] };
    }
  }

  static async analyzeNpm(name, sources, version, options = {}) {
    const normalized = String(name || '').trim().toLowerCase();
    if (!normalized) return { name, error: 'Invalid package name', sources, advisories: [] };

    const useOsv = options.osvLookup !== false;

    const cacheKey = `npm:${normalized}`;
    const now = Date.now();
    const cachedEntry = MessageHandler.registryCache.get(cacheKey);
    let registryData;
    if (cachedEntry && (now - cachedEntry.timestamp) < MessageHandler.REGISTRY_CACHE_TTL) {
      registryData = cachedEntry.value;
    } else {
      try {
        registryData = await this.fetchNpmMetadata(normalized);
      } catch (e) {
        registryData = { error: e.name === 'AbortError' ? 'Registry timeout' : (e.message || 'Network error') };
      }
      MessageHandler.registryCache.set(cacheKey, { value: registryData, timestamp: now });
    }

    const osvResult = useOsv
      ? await OsvChecker.lookup('npm', normalized, version)
      : { advisories: [] };

    if (registryData.error === 'HTTP 404') {
      return {
        name: normalized,
        suspicious: true,
        isUnregistered: true,
        riskLevel: 'CRITICAL',
        riskReasons: ['Package not found on npmjs.org - potential dependency confusion'],
        sources,
        advisories: (osvResult.advisories || []).slice(0, 3),
        advisoriesCount: (osvResult.advisories || []).length,
        osvError: osvResult.osvError
      };
    }

    if (registryData.error) {
      if (registryData.error === 'Rate Limit Exceeded (429)') {
        return { name: normalized, error: 'Rate Limit Exceeded (429)', sources, advisories: [] };
      }
      return { name: normalized, error: `Registry Error: ${registryData.error}`, sources, advisories: [] };
    }

    const info = registryData.info || {};
    const downloads = registryData.downloads || 0;
    const baseAssessment = NpmRiskHeuristics.assess(info, downloads);

    const advisories = osvResult.advisories || [];
    const finalLevel = NpmRiskHeuristics.applyAdvisoryRisk(baseAssessment.riskLevel, advisories);

    const advisoryReasons = advisories.length > 0 ? [`${advisories.length} OSV advisory/advisories`] : [];

    return {
      name: normalized,
      version: info['dist-tags']?.latest || version || '?',
      weeklyDownloads: downloads,
      suspicious: baseAssessment.suspicious || advisories.length > 0,
      riskLevel: finalLevel,
      riskReasons: [...baseAssessment.riskReasons, ...advisoryReasons],
      sources,
      advisories: advisories.slice(0, 3),
      advisoriesCount: advisories.length,
      osvError: osvResult.osvError
    };
  }

  static registryCache = new LRUCache(256);
  static REGISTRY_CACHE_TTL = 5 * 60 * 1000;

  static async fetchNpmMetadata(normalized) {
    const encoded = encodeURIComponent(normalized);

    // Concurrently fetch weekly downloads
    const downloadsPromise = this.fetchWithTimeout(`https://api.npmjs.org/downloads/point/last-week/${encoded}`)
      .then(r => r.ok ? r.json() : null)
      .catch(() => null);

    // Concurrently fetch package manifest: request /latest first (returns ~2KB instead of 7MB packument)
    let res = await this.fetchWithTimeout(`https://registry.npmjs.org/${encoded}/latest`);

    // If /latest returned 404, check the root packument (abbreviated) in case it has only non-latest dist tags
    if (res.status === 404) {
      const rootRes = await this.fetchWithTimeout(`https://registry.npmjs.org/${encoded}`, {
        headers: { 'Accept': 'application/vnd.npm.install-v1+json' }
      });
      if (rootRes.status === 404) return { error: 'HTTP 404' };
      res = rootRes;
    }

    if (res.status === 429) return { error: 'Rate Limit Exceeded (429)' };
    if (!res.ok) return { error: `HTTP ${res.status}` };

    const [info, dlData] = await Promise.all([
      res.json(),
      downloadsPromise
    ]);

    const downloads = Number(dlData?.downloads) || 0;
    return { info, downloads };
  }

  static async analyzeGeneric(ecosystem, name, sources, options = {}) {
    const useOsv = options.osvLookup !== false;
    const cacheKey = `${ecosystem}:${name}`;
    const now = Date.now();

    const cachedEntry = MessageHandler.registryCache.get(cacheKey);
    let exists;
    if (cachedEntry && (now - cachedEntry.timestamp) < MessageHandler.REGISTRY_CACHE_TTL) {
      exists = cachedEntry.value;
    } else {
      exists = await this.checkRegistryExists(ecosystem, name);
      MessageHandler.registryCache.set(cacheKey, { value: exists, timestamp: now });
    }

    const osvResult = useOsv
      ? await OsvChecker.lookup(ecosystem, name)
      : { advisories: [] };

    if (!exists) {
      const advisories = (osvResult.advisories || []).slice(0, 3);
      return {
        name,
        ecosystem,
        suspicious: true,
        isUnregistered: true,
        riskLevel: 'CRITICAL',
        riskReasons: [`Package not found on public ${ecosystem} registry - potential dependency confusion`],
        sources,
        advisories,
        advisoriesCount: advisories.length,
        osvError: osvResult.osvError
      };
    }

    const advisories = (osvResult.advisories || []).slice(0, 3);
    const baseLevel = 'LOW';
    const finalLevel = NpmRiskHeuristics.applyAdvisoryRisk(baseLevel, advisories);

    return {
      name,
      ecosystem,
      suspicious: advisories.length > 0,
      isUnregistered: false,
      riskLevel: finalLevel,
      riskReasons: advisories.length > 0 ? [`${advisories.length} OSV advisory/advisories`] : [],
      sources,
      advisories,
      advisoriesCount: advisories.length,
      osvError: osvResult.osvError
    };
  }

  static async checkRegistryExists(ecosystem, name) {
    try {
      switch (ecosystem) {
        case 'pypi': {
          const res = await this.fetchWithTimeout(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
          return res.ok;
        }
        case 'rubygems': {
          const res = await this.fetchWithTimeout(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`);
          return res.ok;
        }
        case 'nuget': {
          const normalized = encodeURIComponent(name.toLowerCase());
          const res = await this.fetchWithTimeout(`https://api.nuget.org/v3-flatcontainer/${normalized}/index.json`);
          return res.ok;
        }
        case 'maven': {
          if (!name.includes(':')) return false;
          const [groupId, artifactId] = name.split(':', 2);
          const query = `g:"${groupId}" AND a:"${artifactId}"`;
          const url = `https://search.maven.org/solrsearch/select?q=${encodeURIComponent(query)}&rows=1&wt=json`;
          const res = await this.fetchWithTimeout(url);
          if (!res.ok) return false;
          const data = await res.json();
          return Boolean(data.response && data.response.numFound > 0);
        }
        case 'composer': {
          const res = await this.fetchWithTimeout(`https://repo.packagist.org/p2/${encodeURIComponent(name).replace(/%2F/g, '/')}.json`);
          return res.ok;
        }
        case 'golang': {
          const encoded = encodeURIComponent(name).replace(/%2F/g, '/');
          const res = await this.fetchWithTimeout(`https://proxy.golang.org/${encoded}/@v/list`);
          return res.ok;
        }
        case 'crates': {
          const res = await this.fetchWithTimeout(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, {
            headers: { 'User-Agent': 'Crawlizer-Security-Scanner (contact@crawlizer.io)' }
          });
          return res.ok;
        }
        default:
          return false;
      }
    } catch (e) {
      return true;
    }
  }
}

// ============================================================================
// STANDALONE IN-TAB CONTENT EXTRACTION SCRIPT (Runs inside opened tabs)
// ============================================================================

function katanaInTabExtractionScript() {
  const result = {
    captchaDetected: false,
    challengeType: null,
    pageUrl: window.location.href,
    htmlLinks: [],
    scriptSources: [],
    formActions: [],
    inlineScripts: [],
    dataEndpoints: [],
    networkResources: [],
    htmlComments: [],
    metaLinks: [],
    jsonBlobs: [],
    rawHtml: '',
    cssSources: [],
    inlineStyles: []
  };

  try {
    const title = (document.title || '').toLowerCase();
    const bodyText = (document.body ? document.body.innerText || '' : '').toLowerCase().slice(0, 3000);
    const hasNormalContent = bodyText.length > 500 && !title.includes('just a moment') && !title.includes('attention required');

    const isCloudflare = !hasNormalContent && (
      title.includes('just a moment') ||
      title.includes('attention required! | cloudflare') ||
      document.querySelector('#cf-challenge-running') !== null ||
      (document.querySelector('#challenge-form') !== null && (title.includes('moment') || bodyText.includes('challenge'))) ||
      (document.querySelector('iframe[src*="challenges.cloudflare.com"]') !== null && (title.includes('just a moment') || title.includes('cloudflare')))
    );

    const isBlockingCaptcha = !hasNormalContent && (
      (title.includes('captcha') || title.includes('security check') || title.includes('bot verification') || title.includes('are you human')) &&
      (bodyText.includes('verify you are human') || bodyText.includes('please solve the challenge') || bodyText.includes('confirm you are not a robot'))
    );

    if (isCloudflare) {
      result.captchaDetected = true;
      result.challengeType = 'Cloudflare Challenge / Turnstile';
      return result;
    } else if (isBlockingCaptcha) {
      result.captchaDetected = true;
      result.challengeType = 'Bot Verification / Captcha';
      return result;
    }
  } catch (e) {}

  const base = document.baseURI || window.location.href;

  // Extract DOM links
  try {
    document.querySelectorAll('a[href], link[href], area[href], iframe[src], embed[src], object[data], source[src], video[src], audio[src]').forEach(el => {
      try {
        if (el.href && typeof el.href === 'string' && /^https?:\/\//i.test(el.href)) {
          if (!result.htmlLinks.includes(el.href)) result.htmlLinks.push(el.href);
        } else if (el.src && typeof el.src === 'string' && /^https?:\/\//i.test(el.src)) {
          if (!result.htmlLinks.includes(el.src)) result.htmlLinks.push(el.src);
        }
        const val = el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('data');
        if (val) {
          try {
            const resolved = new URL(val, base).href;
            if (/^https?:\/\//i.test(resolved) && !result.htmlLinks.includes(resolved)) {
              result.htmlLinks.push(resolved);
            }
          } catch(e) {
            if (!result.htmlLinks.includes(val)) result.htmlLinks.push(val);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Extract Script sources
  try {
    document.querySelectorAll('script[src]').forEach(el => {
      try {
        const src = el.src || el.getAttribute('src');
        if (src) {
          try {
            const resolved = new URL(src, base).href;
            if (!result.scriptSources.includes(resolved)) result.scriptSources.push(resolved);
          } catch(e) {
            if (!result.scriptSources.includes(src)) result.scriptSources.push(src);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Extract Form actions
  try {
    document.querySelectorAll('form[action], input[formaction], button[formaction]').forEach(el => {
      try {
        const rawAction = el.getAttribute('action') || el.getAttribute('formaction') || '';
        const method = (el.getAttribute('method') || 'GET').toUpperCase();
        if (rawAction) {
          try {
            const resolved = new URL(rawAction, base).href;
            result.formActions.push({ action: resolved, method });
          } catch(e) {
            result.formActions.push({ action: rawAction, method });
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Extract Inline Scripts & JSON routing blobs
  try {
    document.querySelectorAll('script:not([src])').forEach(script => {
      try {
        const content = script.textContent || '';
        if (content.length > 5 && content.length < 500000) {
          const type = (script.getAttribute('type') || '').toLowerCase();
          const id = (script.id || '').toLowerCase();
          if (type.includes('json') || type === 'importmap' || id.includes('next') || id.includes('nuxt')) {
            result.jsonBlobs.push(content);
          } else {
            result.inlineScripts.push(content);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Extract Meta tag URLs
  try {
    document.querySelectorAll('meta[content*="/"], meta[content*="http"]').forEach(m => {
      try {
        const c = m.getAttribute('content');
        if (c && c.length > 1 && c.length < 2000) {
          try {
            const resolved = new URL(c, base).href;
            result.metaLinks.push(resolved);
          } catch(e) {
            result.metaLinks.push(c);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Extract CSS stylesheets
  try {
    document.querySelectorAll('link[rel~="stylesheet"][href]').forEach(el => {
      try {
        const href = el.href || el.getAttribute('href');
        if (href) {
          try {
            const resolved = new URL(href, base).href;
            result.cssSources.push(resolved);
          } catch(e) {
            result.cssSources.push(href);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // Capture HTML slice
  try {
    result.rawHtml = document.documentElement ? document.documentElement.outerHTML.slice(0, 300000) : '';
  } catch(e) {
    result.rawHtml = '';
  }

  return result;
}

// ============================================================================
// LOCAL SERVER AGENT (Connects to http://localhost:4488)
// ============================================================================

class LocalServerAgent {
  constructor(port = 4488) {
    this.port = port;
    this.wsUrl = `ws://localhost:${port}/ws`;
    this.ws = null;
    this.connected = false;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.activeCrawlerTabId = null;
    this.secretScanner = (typeof KatanaSecretScanner !== 'undefined') ? new KatanaSecretScanner() : null;
    this.supplyScanner = (typeof KatanaSupplyChainScanner !== 'undefined') ? new KatanaSupplyChainScanner() : null;
  }

  startHeartbeat() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = setInterval(async () => {
      if (this.connected && this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.send({ type: 'ping' });
        try {
          // Touch Chrome API to reset service worker 30s inactivity timer
          await chrome.runtime.getPlatformInfo();
        } catch {}
      } else {
        this.connect();
      }
    }, 12000);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    try {
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        this.connected = true;
        console.log(`[Crawlizer Agent] Connected to Local Server at ${this.wsUrl}`);
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }

        this.startHeartbeat();

        this.send({
          type: 'register:agent',
          client: 'chrome-extension',
          version: '1.0.5',
          name: 'Chrome Extension Crawler Agent'
        });

        chrome.storage.local.set({ localServerConnected: true, localServerPort: this.port });
      };

      this.ws.onmessage = async (event) => {
        try {
          const msg = JSON.parse(event.data);
          await this.handleServerCommand(msg);
        } catch (e) {
          console.warn('[Crawlizer Agent] Message parse error:', e);
        }
      };

      this.ws.onclose = () => {
        this.connected = false;
        this.stopHeartbeat();
        chrome.storage.local.set({ localServerConnected: false });
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.connected = false;
        this.stopHeartbeat();
        try { this.ws.close(); } catch {}
      };
    } catch (err) {
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 3000);
  }

  send(payload) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    }
  }

  async handleServerCommand(msg) {
    if (msg.type === 'pong') return;
    if (msg.type === 'crawl:job') {
      await this.executeCrawlJob(msg.url);
    } else if (msg.type === 'crawl:active_tab') {
      await this.executeActiveTabAudit();
    } else if (msg.type === 'crawl:stop') {
      await this.abortCurrentJob();
    }
  }

  async executeCrawlJob(targetUrl) {
    let tabId = null;
    try {
      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Opening browser tab to scan: ${targetUrl}`
      });
      console.log(`[Crawlizer Agent] Opening background tab to scan: ${targetUrl}`);
      
      const tab = await chrome.tabs.create({ url: targetUrl, active: false });
      tabId = tab.id;
      this.activeCrawlerTabId = tabId;

      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Tab opened (ID ${tabId}) for ${targetUrl}. Loading DOM...`
      });

      await this.waitForTabReady(tabId, 8000);

      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Extracting links, scripts & scanning secrets on ${targetUrl}...`
      });

      let extracted = null;
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          const tabInfo = await chrome.tabs.get(tabId);
          if (!tabInfo || !tabInfo.url || tabInfo.url.startsWith('chrome://')) break;
          const results = await chrome.scripting.executeScript({
            target: { tabId },
            func: katanaInTabExtractionScript
          });
          if (results && results[0] && results[0].result) {
            extracted = results[0].result;
            break;
          }
        } catch (scriptErr) {
          await new Promise(r => setTimeout(r, 600));
        }
      }
      const findings = await this.analyzeExtractedData(targetUrl, extracted);

      try {
        await chrome.tabs.remove(tabId);
      } catch {}
      this.activeCrawlerTabId = null;

      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Tab closed. Discovered ${findings.urls.length} URLs, ${findings.secrets.length} secrets, ${findings.supplyChain.length} packages.`
      });

      this.send({
        type: 'agent:findings',
        targetUrl,
        urls: findings.urls,
        secrets: findings.secrets,
        supplyChain: findings.supplyChain
      });

    } catch (err) {
      console.warn(`[Crawlizer Agent] Failed crawling ${targetUrl}:`, err);
      if (tabId) {
        try { await chrome.tabs.remove(tabId); } catch {}
      }
      this.activeCrawlerTabId = null;

      this.send({
        type: 'agent:log',
        level: 'wrn',
        message: `Notice while scanning ${targetUrl}: ${err.message}`
      });

      this.send({
        type: 'agent:findings',
        targetUrl,
        urls: [],
        secrets: [],
        supplyChain: []
      });
    }
  }

  async executeActiveTabAudit() {
    try {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab || !activeTab.id || !activeTab.url || activeTab.url.startsWith('chrome://')) {
        this.send({
          type: 'agent:log',
          level: 'wrn',
          message: `Active tab is invalid or protected (${activeTab ? activeTab.url : 'no tab'}). Please focus on a target web page tab first.`
        });
        return;
      }

      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Auditing active browser tab: ${activeTab.url}`
      });

      const results = await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: katanaInTabExtractionScript
      });

      const extracted = results && results[0] ? results[0].result : null;
      const findings = await this.analyzeExtractedData(activeTab.url, extracted);

      this.send({
        type: 'agent:log',
        level: 'inf',
        message: `Active tab audit complete for ${activeTab.url}: found ${findings.urls.length} URLs, ${findings.secrets.length} secrets, ${findings.supplyChain.length} packages.`
      });

      this.send({
        type: 'agent:findings',
        targetUrl: activeTab.url,
        urls: findings.urls,
        secrets: findings.secrets,
        supplyChain: findings.supplyChain
      });
    } catch (err) {
      console.warn('[Crawlizer Agent] Active tab audit failed:', err);
      this.send({
        type: 'agent:log',
        level: 'err',
        message: `Active tab audit error: ${err.message}`
      });
    }
  }

  async abortCurrentJob() {
    if (this.activeCrawlerTabId) {
      try {
        await chrome.tabs.remove(this.activeCrawlerTabId);
      } catch {}
      this.activeCrawlerTabId = null;
    }
  }

  waitForTabReady(tabId, timeoutMs = 8000) {
    return new Promise(resolve => {
      let resolved = false;
      let timer = null;
      let listener = null;

      const finish = () => {
        if (resolved) return;
        resolved = true;
        if (timer) clearTimeout(timer);
        if (listener) chrome.tabs.onUpdated.removeListener(listener);
        resolve();
      };

      timer = setTimeout(finish, timeoutMs);

      listener = (updatedId, changeInfo) => {
        if (updatedId === tabId && changeInfo.status === 'complete') {
          setTimeout(finish, 800);
        }
      };
      chrome.tabs.onUpdated.addListener(listener);
    });
  }

  async analyzeExtractedData(pageUrl, extracted) {
    const discoveredUrls = [];
    const discoveredSecrets = [];
    const discoveredSupply = [];

    if (!extracted) {
      return { urls: discoveredUrls, secrets: discoveredSecrets, supplyChain: discoveredSupply };
    }

    let origin = '';
    try { origin = new URL(pageUrl).origin; } catch {}

    const addUrl = (url, type) => {
      if (!url || typeof url !== 'string') return;
      if (url.startsWith('javascript:') || url.startsWith('data:') || url.startsWith('mailto:')) return;
      let scope = 'out-of-scope';
      try {
        if (new URL(url).origin === origin) scope = 'in-scope';
      } catch {}
      discoveredUrls.push({ url, type, scope, sourceUrl: pageUrl, discoveredAt: new Date().toISOString() });
    };

    (extracted.htmlLinks || []).forEach(u => addUrl(u, 'href'));
    (extracted.scriptSources || []).forEach(u => addUrl(u, 'script'));
    (extracted.metaLinks || []).forEach(u => addUrl(u, 'meta'));
    (extracted.cssSources || []).forEach(u => addUrl(u, 'css'));
    (extracted.dataEndpoints || []).forEach(d => addUrl(d.value, 'data-endpoint'));

    if (this.secretScanner) {
      if (extracted.rawHtml) {
        const sec = this.secretScanner.scanHtml(extracted.rawHtml, pageUrl);
        discoveredSecrets.push(...sec);
      }
      (extracted.inlineScripts || []).forEach(s => {
        const sec = this.secretScanner.scanCode(s, pageUrl, 'inline-script');
        discoveredSecrets.push(...sec);
      });
    }

    if (this.supplyScanner) {
      (extracted.inlineScripts || []).forEach(s => {
        const items = this.supplyScanner.scanCode(s, pageUrl, 'inline-script');
        discoveredSupply.push(...items);
      });
      (extracted.jsonBlobs || []).forEach(blob => {
        const items = this.supplyScanner.scanJson(blob, pageUrl);
        discoveredSupply.push(...items);
      });
    }

    return {
      urls: discoveredUrls,
      secrets: discoveredSecrets,
      supplyChain: discoveredSupply
    };
  }
}

const localServerAgent = new LocalServerAgent(4488);
localServerAgent.connect();

// Periodic watchdog alarm to prevent MV3 service worker dormancy
try {
  if (typeof chrome !== 'undefined' && chrome.alarms) {
    chrome.alarms.create('crawlizer_agent_watchdog', { periodInMinutes: 0.3 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'crawlizer_agent_watchdog') {
        if (!localServerAgent.connected) {
          localServerAgent.connect();
        }
      }
    });
  }
} catch {}

// ============================================================================
// EVENT LISTENERS & LIFECYCLE
// ============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Handle dashboard opening from popup or other sources
  if (request.action === 'open_dashboard') {
    if (localServerAgent.connected) {
      chrome.tabs.create({ url: `http://localhost:${localServerAgent.port}` });
    } else {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    }
    sendResponse({ status: 'ok', serverConnected: localServerAgent.connected });
    return true;
  }

  // Handle audit active tab request
  if (request.action === 'audit_active_tab') {
    localServerAgent.executeActiveTabAudit().then(() => {
      sendResponse({ status: 'ok' });
    });
    return true;
  }

  // Get local server agent status
  if (request.action === 'get_server_status') {
    sendResponse({
      connected: localServerAgent.connected,
      port: localServerAgent.port
    });
    return true;
  }

  const handlers = {
    notifyRisks: MessageHandler.handleNotifyRisks,
    getResults: MessageHandler.handleGetResults,
    canScan: MessageHandler.handleCanScan,
    recordScan: MessageHandler.handleRecordScan,
    getSettings: MessageHandler.handleGetSettings,
    saveSettings: MessageHandler.handleSaveSettings,
    analyzePackage: MessageHandler.handleAnalyzePackage
  };

  const handler = handlers[request.action];
  if (handler) {
    handler(request, sender)
      .then(response => sendResponse(response))
      .catch(error => {
        console.error(`Error in ${request.action}:`, error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }
  return false;
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await BadgeManager.clearBadge(tabId);
  state.removeTab(tabId);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    await BadgeManager.clearBadge(tabId);
    state.removeTab(tabId);
  }
});

setInterval(() => state.cleanup(), 60000);

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await chrome.storage.sync.set({
      autoScan: true,
      deepCrawl: true,
      osvLookup: true,
      showAllRisks: false
    });
  }
  console.log('Crawlizer Pro v1.0.5 initialized (with Supply Chain Security Scanner)');
});
