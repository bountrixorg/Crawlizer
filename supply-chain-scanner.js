/**
 * Katana Supply Chain Scanner - Ultra-High-Speed In-Stream Dependency & Threat Detection Engine
 * Scans Raw HTML, Rendered DOM, External JS Bundles, CSS, Inline Scripts, JSON Blobs, and Source Maps
 * at the exact same time as Katana Secret Scanner.
 * 
 * Extracts npm, PyPI, Packagist, Cargo, and Go packages, checks dependency confusion risks,
 * probes exposed root manifests (.env, package.json, .npmrc), and queries OSV CVEs in the background.
 */

// ============================================================================
// PRE-COMPILED ULTRA-FAST REGEX ENGINE
// ============================================================================

// 1. Unified Imports & Requires: ES6 import, dynamic import, CommonJS require, export from, AMD, Webpack, SystemJS
const RX_IMPORT_REQUIRE = /(?:(?:import|export)\s+(?:[\w*\s{},$]+\s+from\s+)?|require\s*(?:\.resolve)?\s*\(\s*|import\s*\(\s*|__webpack_require__\s*\(\s*|System\.import\s*\(\s*|define\s*\(\s*\[\s*|require\.ensure\s*\(\s*\[\s*)['"](@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)['"]/g;

// 2. Webpack / Bundler node_modules chunks & chunk paths
const RX_NODE_MODULES = /(?:node_modules|\/node_modules\/|(?<=\/)~[a-zA-Z0-9_.\-]+\/)\/(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)/g;

// 3. Public CDNs (unpkg, jsdelivr, esm.sh, skypack)
const RX_CDN = /(?:cdn\.jsdelivr\.net\/npm\/|unpkg\.com\/|esm\.sh\/|cdn\.skypack\.dev\/)(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)(?:@([0-9a-zA-Z._\-]+))?/g;

// 4. cdnjs.cloudflare.com
const RX_CDNJS = /cdnjs\.cloudflare\.com\/ajax\/libs\/([a-zA-Z0-9_.\-]+)(?:\/([0-9a-zA-Z._\-]+))?/g;

// 5. Python / PyPI requirements.txt
const RX_PYTHON_REQ = /^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=|!=)\s*([0-9a-zA-Z._\-]+)/gm;

// 6. PHP Composer.json dependencies
const RX_COMPOSER = /"([a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-]+)"\s*:\s*"[^"]+"/g;

// 7. Rust Cargo.toml dependencies
const RX_CARGO = /^\s*([a-zA-Z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*|)['"]([0-9a-zA-Z._\-]+)/gm;

// 8. Go go.mod dependencies
const RX_GOMOD = /^\s*([a-zA-Z0-9_.\-\/]+)\s+v([0-9a-zA-Z._\-]+)/gm;

// 9. Exposed sensitive configuration file paths in HTML / JS code
const RX_CONFIG_PATHS = /['"](\/(?:package\.json|package-lock\.json|\.npmrc|\.yarnrc|\.env|\.env\.local|\.env\.development|\.env\.production|requirements\.txt|Pipfile|composer\.json|go\.mod|Cargo\.toml))['"]/gi;

// 10. Fast sourcemap node_modules pattern (extracts package directly from sourcemap sources paths)
const RX_MAP_NODE_MODULES = /(?:(?:webpack:\/\/\/|\/|^)node_modules\/)(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)/g;

// Fast keyword filter: if text does not contain ANY of these substrings, skip scanning in 0.01ms!
const FAST_SCAN_KEYWORDS = [
  'import', 'require', 'node_modules', 'dependencies', 'devDependencies',
  'unpkg', 'jsdelivr', 'cdnjs', 'esm.sh', 'skypack',
  'sources', 'requirements.txt', 'package.json', 'composer.json', 'go.mod', 'Cargo.toml',
  '.npmrc', '.env'
];

class KatanaSupplyChainScanner {
  constructor() {
    this.evaluatedCache = new Map(); // key -> evaluated record
    this.pendingQueries = new Map(); // key -> Promise
    this.probedOrigins = new Set();  // Set of apex origins probed

    // Background evaluation queue
    this.evalQueue = [];
    this.isProcessingQueue = false;
    this.maxConcurrentEval = 6;
    this.activeEvalCount = 0;

    // Node.js standard built-in modules
    this.nodeBuiltins = new Set([
      'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
      'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
      'events', 'fs', 'fs/promises', 'http', 'http2', 'https', 'inspector',
      'module', 'net', 'os', 'path', 'path/posix', 'path/win32', 'perf_hooks',
      'process', 'punycode', 'querystring', 'readline', 'repl', 'stream',
      'stream/promises', 'stream/consumers', 'stream/web', 'string_decoder',
      'sys', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
      'url', 'util', 'util/types', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
    ]);

    // Local / relative path prefixes and framework aliases to ignore
    this.localPrefixes = [
      './', '../', '/', '\\', '@/', '~/', '~~/',
      'src/', 'app/', 'pages/', 'components/', 'assets/', 'lib/', 'utils/',
      'hooks/', 'styles/', 'types/', 'config/', 'public/', 'modules/'
    ];

    // Apex origin manifest & config probe paths
    this.manifestProbePaths = [
      '/package.json',
      '/package-lock.json',
      '/.npmrc',
      '/.env',
      '/.env.local',
      '/requirements.txt',
      '/yarn.lock',
      '/composer.json',
      '/Cargo.toml',
      '/go.mod'
    ];
  }

  /**
   * Fast-path check: does the text contain any dependency or supply chain keywords?
   */
  hasRelevantKeywords(text) {
    if (!text || typeof text !== 'string') return false;
    for (let i = 0; i < FAST_SCAN_KEYWORDS.length; i++) {
      if (text.includes(FAST_SCAN_KEYWORDS[i])) return true;
    }
    return false;
  }

  /**
   * Fast synchronous scan of code / HTML / bundle / sourcemap text to extract referenced packages
   * Runs in microseconds at the exact same time as Katana Secret Scanner.
   */
  scan(text, sourceUrl, sourceType = 'js-bundle') {
    if (!text || typeof text !== 'string' || text.length < 5) return [];

    // Ultra-fast keyword fast-path: skip irrelevant non-code blobs in 0.01ms
    if (!this.hasRelevantKeywords(text)) {
      return [];
    }

    // Guard against multi-gigabyte memory bombs (limit to 2MB)
    const textToScan = text.length > 2000000 ? text.slice(0, 2000000) : text;
    const discovered = new Map(); // key (eco:name) -> item

    const addPackage = (name, version, eco, contextSnippet) => {
      if (!name || typeof name !== 'string') return;
      let cleanName = name.trim();

      // Fast quote and whitespace stripping
      cleanName = cleanName.replace(/^["'`]|["'`]$/g, '').replace(/\/+$/, '');
      if (!cleanName || cleanName.length < 2 || cleanName.length > 100) return;

      // Handle scoped vs unscoped packages
      if (cleanName.startsWith('@')) {
        const parts = cleanName.split('/');
        if (parts.length > 2) cleanName = parts.slice(0, 2).join('/');
      } else if (cleanName.includes('/')) {
        // Unscoped subpath import like 'lodash/merge' -> base package is 'lodash'
        cleanName = cleanName.split('/')[0];
      }

      // Filter local paths, aliases, URL protocols, and built-ins
      const lower = cleanName.toLowerCase();
      if (this.nodeBuiltins.has(lower)) return;
      if (this.localPrefixes.some(p => lower.startsWith(p))) return;
      if (/^(https?:|data:|blob:|file:|\*)/i.test(lower)) return;
      if (lower.endsWith('.html') || lower.endsWith('.htm') || lower.endsWith('.vue') || lower.endsWith('.css')) return;

      // Validate naming syntax
      if (!/^(@[a-z0-9\-~][a-z0-9\-._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/i.test(cleanName)) return;

      // npm package names are lowercase
      const finalName = (eco === 'npm' || !eco) ? lower : cleanName;
      const ecosystem = eco || 'npm';
      const key = `${ecosystem}:${finalName}`;

      if (discovered.has(key)) {
        const existing = discovered.get(key);
        if (!existing.version && version) existing.version = version;
        return;
      }

      discovered.set(key, {
        type: 'package',
        key,
        name: finalName,
        version: version || '',
        ecosystem,
        sourceUrl,
        sourceType,
        context: (contextSnippet || '').slice(0, 140),
        discoveredAt: Date.now()
      });
    };

    // 1. Check if the text is a JSON manifest directly (package.json or importmap)
    if (textToScan.startsWith('{') || textToScan.includes('"dependencies"') || textToScan.includes('"imports"')) {
      // Manifest dependencies
      if (textToScan.includes('"dependencies"')) {
        try {
          const parsed = JSON.parse(textToScan);
          const allDeps = {
            ...(parsed.dependencies || {}),
            ...(parsed.devDependencies || {}),
            ...(parsed.peerDependencies || {}),
            ...(parsed.optionalDependencies || {})
          };
          for (const [depName, depVer] of Object.entries(allDeps)) {
            const cleanVer = String(depVer).replace(/^[\^~>=<]+/, '').trim();
            addPackage(depName, cleanVer, 'npm', `Manifest dependency: ${depName}@${cleanVer}`);
          }
        } catch (e) { /* fallback to regex */ }
      }

      // Import maps (<script type="importmap">)
      if (textToScan.includes('"imports"')) {
        try {
          const parsed = JSON.parse(textToScan);
          const imports = (parsed && parsed.imports) || {};
          for (const [specifier, targetUrl] of Object.entries(imports)) {
            if (!specifier.startsWith('.') && !specifier.startsWith('/') && !specifier.includes('://')) {
              addPackage(specifier, '', 'npm', `Import map: ${specifier} -> ${targetUrl}`);
            }
          }
        } catch (e) {}
      }
    }

    // 2. High-speed Imports & Requires (Unified precompiled regex)
    RX_IMPORT_REQUIRE.lastIndex = 0;
    let m;
    while ((m = RX_IMPORT_REQUIRE.exec(textToScan)) !== null) {
      const matchIdx = m.index;
      const snippet = textToScan.slice(Math.max(0, matchIdx - 20), Math.min(textToScan.length, matchIdx + m[0].length + 20));
      addPackage(m[1], '', 'npm', snippet);
    }

    // 3. Webpack chunk / node_modules bundle paths
    RX_NODE_MODULES.lastIndex = 0;
    while ((m = RX_NODE_MODULES.exec(textToScan)) !== null) {
      const matchIdx = m.index;
      const snippet = textToScan.slice(Math.max(0, matchIdx - 15), Math.min(textToScan.length, matchIdx + m[0].length + 15));
      addPackage(m[1], '', 'npm', snippet);
    }

    // 4. Source map sources paths (if scanning a source map)
    if (sourceType === 'source-map' || sourceUrl.endsWith('.map') || textToScan.includes('"sources"')) {
      RX_MAP_NODE_MODULES.lastIndex = 0;
      while ((m = RX_MAP_NODE_MODULES.exec(textToScan)) !== null) {
        addPackage(m[1], '', 'npm', `Source map module: ${m[0]}`);
      }
    }

    // 5. Public CDNs: jsdelivr, unpkg, esm.sh, skypack
    RX_CDN.lastIndex = 0;
    while ((m = RX_CDN.exec(textToScan)) !== null) {
      addPackage(m[1], m[2] || '', 'npm', m[0]);
    }

    // 6. cdnjs.cloudflare.com
    RX_CDNJS.lastIndex = 0;
    while ((m = RX_CDNJS.exec(textToScan)) !== null) {
      addPackage(m[1], m[2] || '', 'npm', m[0]);
    }

    // 7. Python / PyPI Requirements format
    if (sourceUrl.endsWith('requirements.txt') || textToScan.includes('requirements.txt')) {
      RX_PYTHON_REQ.lastIndex = 0;
      while ((m = RX_PYTHON_REQ.exec(textToScan)) !== null) {
        addPackage(m[1], m[2] || '', 'pypi', m[0]);
      }
    }

    // 8. PHP Composer format
    if (sourceUrl.endsWith('composer.json') || textToScan.includes('composer.json')) {
      RX_COMPOSER.lastIndex = 0;
      while ((m = RX_COMPOSER.exec(textToScan)) !== null) {
        addPackage(m[1], '', 'composer', m[0]);
      }
    }

    // 9. Rust Cargo.toml format
    if (sourceUrl.endsWith('Cargo.toml') || textToScan.includes('Cargo.toml')) {
      RX_CARGO.lastIndex = 0;
      while ((m = RX_CARGO.exec(textToScan)) !== null) {
        addPackage(m[1], m[2] || '', 'crates', m[0]);
      }
    }

    // 10. Go go.mod format
    if (sourceUrl.endsWith('go.mod') || textToScan.includes('go.mod')) {
      RX_GOMOD.lastIndex = 0;
      while ((m = RX_GOMOD.exec(textToScan)) !== null) {
        addPackage(m[1], m[2] || '', 'golang', m[0]);
      }
    }

    // 11. Check for exposed configuration files in HTML or JS endpoints
    if (sourceType === 'html' || sourceType === 'rendered-js') {
      RX_CONFIG_PATHS.lastIndex = 0;
      while ((m = RX_CONFIG_PATHS.exec(textToScan)) !== null) {
        const foundPath = m[1];
        const key = `exposed:${foundPath}`;
        if (!discovered.has(key)) {
          discovered.set(key, {
            type: 'exposed-file',
            key,
            path: foundPath,
            status: 200,
            contentType: 'config',
            riskLevel: 'HIGH',
            riskReasons: ['Exposed sensitive manifest / configuration path referenced in code'],
            sourceUrl,
            sourceType,
            discoveredAt: Date.now()
          });
        }
      }
    }

    return Array.from(discovered.values());
  }

  /**
   * Non-blocking background evaluation queue.
   * Feeds discovered packages into background registry & OSV checks without freezing the crawler!
   */
  queueForEvaluation(findingsList, onEvaluatedCallback) {
    if (!Array.isArray(findingsList) || findingsList.length === 0) return;

    for (const item of findingsList) {
      if (!item || item.type !== 'package') continue;
      const cacheKey = `${item.ecosystem || 'npm'}:${item.name}`;

      // Instant cache hit: invoke callback immediately!
      if (this.evaluatedCache.has(cacheKey)) {
        const cached = this.evaluatedCache.get(cacheKey);
        const merged = {
          ...item,
          isUnregistered: Boolean(cached.isUnregistered),
          riskLevel: cached.riskLevel || 'LOW',
          riskReasons: cached.riskReasons || [],
          weeklyDownloads: cached.weeklyDownloads != null ? cached.weeklyDownloads : 0,
          advisories: cached.advisories || [],
          advisoriesCount: cached.advisoriesCount || 0,
          evaluatedAt: cached.evaluatedAt
        };
        if (onEvaluatedCallback) onEvaluatedCallback(merged);
        continue;
      }

      this.evalQueue.push({ item, callback: onEvaluatedCallback });
    }

    this.processQueue();
  }

  /**
   * Processes the background evaluation queue with bounded concurrency
   */
  async processQueue() {
    if (this.isProcessingQueue) return;
    this.isProcessingQueue = true;

    while (this.evalQueue.length > 0 && this.activeEvalCount < this.maxConcurrentEval) {
      const task = this.evalQueue.shift();
      if (!task) break;

      this.activeEvalCount++;
      (async () => {
        try {
          const evaluated = await this.evaluatePackage(task.item);
          if (task.callback) task.callback(evaluated);
        } catch (err) {
          console.warn('[KatanaSupplyChain] Evaluation worker error:', err);
        } finally {
          this.activeEvalCount--;
          this.processQueue();
        }
      })();
    }

    this.isProcessingQueue = false;
  }

  /**
   * Evaluates a package finding with the background service worker (registry check & OSV CVE lookups)
   * Uses in-memory caching for sub-millisecond return on seen packages!
   */
  async evaluatePackage(item) {
    if (!item || item.type !== 'package') return item;
    const cacheKey = `${item.ecosystem || 'npm'}:${item.name}`;

    if (this.evaluatedCache.has(cacheKey)) {
      const cached = this.evaluatedCache.get(cacheKey);
      return {
        ...item,
        isUnregistered: Boolean(cached.isUnregistered),
        riskLevel: cached.riskLevel || 'LOW',
        riskReasons: cached.riskReasons || [],
        weeklyDownloads: cached.weeklyDownloads != null ? cached.weeklyDownloads : 0,
        advisories: cached.advisories || [],
        advisoriesCount: cached.advisoriesCount || 0,
        evaluatedAt: cached.evaluatedAt
      };
    }

    if (this.pendingQueries.has(cacheKey)) {
      return this.pendingQueries.get(cacheKey);
    }

    const queryPromise = (async () => {
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'analyzePackage',
          name: item.name,
          ecosystem: item.ecosystem || 'npm',
          version: item.version,
          sources: [{ url: item.sourceUrl, context: item.context }],
          options: { osvLookup: true }
        });

        if (response) {
          this.evaluatedCache.set(cacheKey, {
            ...response,
            evaluatedAt: Date.now()
          });

          return {
            ...item,
            isUnregistered: Boolean(response.isUnregistered),
            riskLevel: response.riskLevel || (response.isUnregistered ? 'CRITICAL' : 'LOW'),
            riskReasons: response.riskReasons || [],
            weeklyDownloads: response.weeklyDownloads != null ? response.weeklyDownloads : 0,
            advisories: response.advisories || [],
            advisoriesCount: response.advisoriesCount || (response.advisories ? response.advisories.length : 0),
            error: response.error,
            evaluatedAt: Date.now()
          };
        }
      } catch (err) {
        console.warn(`[SupplyChainScanner] Background evaluation failed for ${item.name}:`, err);
      } finally {
        this.pendingQueries.delete(cacheKey);
      }
      return item;
    })();

    this.pendingQueries.set(cacheKey, queryPromise);
    return queryPromise;
  }

  /**
   * Fast root origin probe for exposed manifest & secret config files
   */
  async probeOriginManifests(pageUrl, fetchFn) {
    if (!pageUrl || !fetchFn) return [];
    let origin = '';
    try {
      origin = new URL(pageUrl).origin;
    } catch {
      return [];
    }

    if (this.probedOrigins.has(origin)) return [];
    this.probedOrigins.add(origin);

    const findings = [];
    const probePromises = this.manifestProbePaths.map(async (relPath) => {
      const probeUrl = `${origin}${relPath}`;
      try {
        const resp = await fetchFn(probeUrl, { timeout: 2500 });
        if (resp && resp.ok) {
          const contentType = resp.headers?.get ? (resp.headers.get('content-type') || '') : '';
          const text = await resp.text();

          // If response looks like an HTML error/404 page masquerading as 200, skip it
          if (text.includes('<!DOCTYPE html>') && (relPath.endsWith('.json') || relPath.endsWith('.txt') || relPath.endsWith('.npmrc') || relPath.endsWith('.env'))) {
            return;
          }

          findings.push({
            type: 'exposed-file',
            key: `exposed:${relPath}`,
            path: relPath,
            url: probeUrl,
            status: resp.status,
            contentType: contentType || 'text/plain',
            riskLevel: 'HIGH',
            riskReasons: [`Exposed configuration file found at ${probeUrl}`],
            rawContent: text.slice(0, 50000),
            sourceUrl: probeUrl,
            sourceType: 'probe',
            discoveredAt: Date.now()
          });

          // If it is a manifest, immediately parse its dependencies!
          if (relPath === '/package.json' || relPath === '/requirements.txt' || relPath === '/composer.json') {
            const parsedPkgs = this.scan(text, probeUrl, 'manifest');
            findings.push(...parsedPkgs);
          }
        }
      } catch (e) { /* ignore network timeouts */ }
    });

    await Promise.allSettled(probePromises);
    return findings;
  }
}

if (typeof window !== 'undefined') {
  window.KatanaSupplyChainScanner = KatanaSupplyChainScanner;
  window.katanaSupplyChainScanner = new KatanaSupplyChainScanner();
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KatanaSupplyChainScanner };
}
