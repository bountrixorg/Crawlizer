/**
 * NPM Security Scanner Pro - Content Script (Full Crawler Edition)
 * Performs comprehensive security analysis with deep crawling
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  API_RATE_LIMIT: 50,
  API_WINDOW: 60000,
  SCAN_COOLDOWN: 5000,
  CACHE_DURATION: 300000, // 5 minutes
  MIN_DOWNLOADS_SUSPICIOUS: 100,
  MIN_DOWNLOADS_NEW: 1000,
  NEW_PACKAGE_DAYS: 90,
  ABANDONED_DAYS: 365,

  // Crawler settings
  MAX_CRAWL_DEPTH: 3,
  MAX_FILES_PER_TYPE: 50,
  MAX_DISCOVERED_URLS: 120,
  MAX_ANALYSIS_PACKAGES: 140,
  MAX_CONCURRENT_REQUESTS: 10, // For crawling
  MAX_CONCURRENT_SCANS: 5,     // For directory brute-forcing
  REQUEST_TIMEOUT: 8000,
  STAGE_TIMEOUT: 15000,
  TOTAL_SCAN_TIMEOUT: 45000,

  // File patterns to search for
  SCRIPT_PATTERNS: [
    '*.js', '*.mjs', '*.jsx', '*.ts', '*.tsx',
    'bundle.*.js', 'vendor.*.js', 'main.*.js', 'app.*.js', 'chunk.*.js'
  ],

  // Common directories to check
  COMMON_DIRS: [
    '/static/js/', '/static/scripts/', '/assets/js/', '/assets/scripts/',
    '/js/', '/scripts/', '/dist/', '/build/', '/out/',
    '/_next/static/', '/_nuxt/', '/webpack/',
    '/.next/', '/public/', '/lib/', '/src/'
  ],

  // Configuration files to check (Expanded)
  CONFIG_FILES: [
    // Node/NPM
    '/package.json',
    '/package-lock.json',
    '/yarn.lock',
    '/pnpm-lock.yaml',
    '/npm-shrinkwrap.json',
    '/.npmrc',
    '/.yarnrc',
    '/.yarnrc.yml',
    '/node_modules/',

    // Python / PyPI
    '/requirements.txt',
    '/Pipfile',
    '/Pipfile.lock',

    // Ruby / RubyGems
    '/Gemfile',
    '/Gemfile.lock',

    // .NET / NuGet
    '/packages.config',

    // Java / Maven / Gradle
    '/pom.xml',
    '/build.gradle',
    '/build.gradle.kts',

    // PHP / Composer
    '/composer.json',

    // Go
    '/go.mod',
    '/go.sum',

    // Rust / Crates
    '/Cargo.toml',
    '/Cargo.lock',

    // Bundlers/Frameworks
    '/webpack.config.js',
    '/vite.config.js',
    '/vite.config.ts',
    '/next.config.js',
    '/nuxt.config.js',
    '/rollup.config.js',
    '/babel.config.js',
    '/tsconfig.json',

    // Environment/Secrets
    '/.env',
    '/.env.local',
    '/.env.development',
    '/.env.production',
    '/.env.test',
    '/docker-compose.yml',
    '/Dockerfile'
  ],

  NODE_BUILTINS: new Set([
    'assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns',
    'domain', 'events', 'fs', 'http', 'https', 'net', 'os', 'path', 'punycode',
    'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'timers',
    'tls', 'tty', 'url', 'util', 'v8', 'vm', 'zlib', 'constants', 'module',
    'process', 'console', 'http2', 'perf_hooks', 'trace_events', 'worker_threads',
    'require', 'exports'
  ]),

  // Common path aliases used by bundlers/frameworks
  INTERNAL_ALIAS_PREFIXES: ['@/', '~/', '~~/'],
  INTERNAL_ALIAS_ROOTS: [
    'src', 'app', 'apps', 'components', 'component', 'pages', 'layouts', 'views',
    'hooks', 'utils', 'lib', 'libs', 'services', 'service', 'store', 'stores',
    'state', 'modules', 'assets', 'styles', 'css', 'scss', 'sass', 'less',
    'images', 'img', 'fonts', 'locales', 'i18n', 'types', 'constants',
    'config', 'configs', 'public'
  ],

  CONFIG_PATTERNS: {
    'package.json': /^\s*\{/,
    'package-lock.json': /^\s*\{/,
    'yarn.lock': /^#.*yarn|registry/i,
    'pnpm-lock.yaml': /^lockfileVersion/,
    'npm-shrinkwrap.json': /^\s*\{/,
    '.npmrc': /registry=|disturl=|always-auth=|_auth=/,
    '.yarnrc': /--install|yarn-path/,
    '.yarnrc.yml': /nodeLinker:|yarnPath:/,
    'node_modules': /Index of|Parent Directory/i,
    'requirements.txt': /^[a-zA-Z0-9_.-]+/m,
    'Pipfile': /^\[(packages|dev-packages)\]/m,
    'Pipfile.lock': /^\s*\{/,
    'Gemfile': /^\s*source\s+['"]|^\s*gem\s+['"]/m,
    'Gemfile.lock': /^GEM\b/m,
    'packages.config': /<packages>|<package\s+id=/i,
    'pom.xml': /<project[\s>]/i,
    'build.gradle': /\bdependencies\b|\bplugins\b/i,
    'build.gradle.kts': /\bdependencies\b|\bplugins\b/i,
    'composer.json': /^\s*\{/,
    'go.mod': /^\s*module\s+/m,
    'go.sum': /^[a-zA-Z0-9_.-]+\s+[v0-9]/m,
    'Cargo.toml': /^\s*\[(dependencies|dev-dependencies|build-dependencies)\]/m,
    'Cargo.lock': /^\s*\[\[package\]\]/m,
    'webpack.config.js': /module\.exports|require\(|import /,
    'vite.config.js': /export default|defineConfig/,
    'vite.config.ts': /export default|defineConfig/,
    'next.config.js': /module\.exports|nextConfig/,
    'nuxt.config.js': /export default|defineNuxtConfig/,
    'rollup.config.js': /export default/,
    'babel.config.js': /module\.exports/,
    'tsconfig.json': /^\s*\{/,
    '.env': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.local': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.development': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.production': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.test': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    'docker-compose.yml': /^version:|services:/,
    'Dockerfile': /^FROM /i
  },

  // Internal module patterns - these are NOT standalone npm packages
  // but internal references within parent packages
  INTERNAL_MODULE_PATTERNS: [
    { parent: 'prismjs', pattern: /^prism-[a-z]+$/ }, // prism-javascript, prism-python, etc.
    { parent: 'highlight.js', pattern: /^highlight\.js\/lib\/languages\// },
    { parent: 'monaco-editor', pattern: /^monaco-editor\/esm\// },
    { parent: 'codemirror', pattern: /^codemirror\/mode\// },
    { parent: 'codemirror', pattern: /^codemirror\/addon\// },
    { parent: 'ace-builds', pattern: /^ace\/mode\// },
    { parent: 'ace-builds', pattern: /^ace\/theme\// },
    // Babel runtime helpers (only meaningful when @babel/runtime is a real dep)
    { parent: '@babel/runtime', pattern: /^@babel\/runtime\/(helpers|core-js|regenerator|helpers\/esm)/ },
    // RxJS internal paths
    { parent: 'rxjs', pattern: /^rxjs\/(internal|operators|testing|ajax|fetch|webSocket|dist)/ },
    // Swiper nested modules
    { parent: 'swiper', pattern: /^swiper\/(components|modules|core|shared|element|vue)/ },
    // lodash submodule imports
    { parent: 'lodash', pattern: /^lodash\/[a-zA-Z0-9_]+$/ },
    { parent: 'lodash-es', pattern: /^lodash-es\/.+$/ },
    // Ant Design deep imports
    { parent: 'antd', pattern: /^antd\/(es|lib|dist)\// },
    { parent: 'antd', pattern: /^antd\/lib\/[a-z-]+(\/style)?$/ },
    // MUI deep imports
    { parent: '@mui/material', pattern: /^@mui\/material\/(styles|colors|utils|internal|esm|lab)/ },
    { parent: '@mui/system', pattern: /^@mui\/system\/(styles|colors|utils|esm)/ },
    // Angular bundles
    { parent: null, pattern: /^@angular\/.+?\/(schematics|testing|bundles|fesm|esm)\// },
    // Ember internals
    { parent: 'ember-source', pattern: /^ember-source\// },
    { parent: 'ember-cli', pattern: /^ember-cli\// },
    // Vue internals
    { parent: 'vue', pattern: /^vue\/(dist|esm|server|shared|compiler-sfc|compiler-dom|compiler-core|compiler-ssr)/ },
    { parent: 'react-dom', pattern: /^react-dom\/(client|server|test-utils)/ },
    // date-fns locales
    { parent: 'date-fns', pattern: /^date-fns\/(locale|esm)/ },
    // Emotion deep imports
    { parent: '@emotion', pattern: /^@emotion\/(react|styled|cache|memoize|serialize|utils|hash|unitless|is-prop-valid|babel-plugin|stylis|weak-memoize|ssr|jsx|colors|escape|compose)/ },
    // Polymer / Web Components (Common False Positives)
    { parent: null, pattern: /^(dom-module|custom-style|ps-dom-if|ps-dom-repeat)$/ },
    { parent: null, pattern: /^(iron-|paper-|neon-|app-).+$/ }, // Common Polymer prefixes
    { parent: null, pattern: /^polymer-.+$/ },
    // YouTube Internal
    { parent: null, pattern: /^yt-.+$/ },
    { parent: null, pattern: /^ytd-.+$/ },
    // Common monorepo workspaces (treat as internal)
    { parent: null, pattern: /^(packages|apps|libs|tools|scripts|fixtures|examples|docs|__tests__|test-utils|shared)\/.+$/ }
  ],

  // Legitimate versioned package names that look like typosquats but aren't.
  // Used to relax the digit-confusable heuristic.
  KNOWN_VERSIONED_NAMES: new Set([
    'vue2', 'vue3', 'react16', 'react17', 'react18', 'react19',
    'webpack4', 'webpack5', 'typescript3', 'typescript4', 'typescript5',
    'auth0', 'auth-0', 'level0', 'level-0', 'saas0', 'saas1', 'saas10',
    'lerna2', 'lerna3', 'lerna4', 'ionic1', 'ionic3', 'ionic4', 'ionic5',
    'node12', 'node14', 'node16', 'node18', 'node20', 'node22',
    'es5', 'es6', 'es7', 'es2015', 'es2017', 'es2020', 'es2021', 'es2022',
    'log10', 'log0', '10print', '10x', '100', '0x'
  ])
};

// ============================================================================
// UTILITIES
// ============================================================================

class Logger {
  static debug(...args) {
    // Always log in development, or check a flag
    console.log('%c[NPM Scanner]', 'color: #00ff41; font-weight: bold;', ...args);
  }

  static error(...args) {
    console.error('%c[NPM Scanner]', 'color: #ff0000; font-weight: bold;', ...args);
  }

  static warn(...args) {
    console.warn('%c[NPM Scanner]', 'color: #ff9900; font-weight: bold;', ...args);
  }
}

class RateLimiter {
  constructor(maxRequests, timeWindow) {
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
    this.requests = [];
  }

  async waitForSlot() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);

    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const waitTime = this.timeWindow - (now - oldestRequest) + 100;
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return this.waitForSlot();
    }

    this.requests.push(now);
  }
}

class PackageNameExtractor {
  /**
   * Check if a package name is likely an internal module (not a real npm package)
   * @param {string} packageName - The package name to check
   * @param {Set} detectedPackages - Set of all detected package names (to check for parent packages)
   * @returns {boolean} - True if this is likely an internal module
   */
  /**
   * Strip JS/TS comments, template literals, and TS type-only imports/exports from a
   * string. Run before any import/require pattern matching so that documentation,
   * banners, template strings, and type definitions don't pollute the package list.
   */
  static stripNonCode(content) {
    if (!content || typeof content !== 'string') return '';
    return content
      // Block comments (multi-line) — non-greedy to avoid eating huge sections.
      .replace(/\/\*[\s\S]*?\*\//g, '')
      // Line comments.
      .replace(/\/\/[^\n]*/g, '')
      // Template literals with backticks (string content that may mention `import`/`require`).
      .replace(/`(?:\\.|[^`\\])*`/g, '""')
      // TypeScript `type` specifier inside an import brace list: import { type X, Y as Z } from 'y'
      .replace(/\bimport\s*\{([^}]*)\}\s*from\s*['"][^'"]+['"]/g, (m, inner) => {
        const cleaned = inner.replace(/^\s*type\s+[A-Za-z_$][\w$]*\s*(?:,\s*)?/g, '');
        return `import {${cleaned}} from ''`;
      })
      // TypeScript type-only import/export declarations (entire statement).
      .replace(/(?:^|[\s;])import\s+type\s+[^;]*?from\s+['"][^'"]+['"]\s*;?/g, '')
      .replace(/(?:^|[\s;])export\s+type\s+[^;]*?from\s+['"][^'"]+['"]\s*;?/g, '')
      // Hash comments (Python, YAML, etc.) for non-JS file content.
      .replace(/^\s*#.*$/gm, '');
  }

  static isInternalModule(packageName, detectedPackages = new Set()) {
    if (!packageName) return false;

    // Check against known internal module patterns
    for (const pattern of CONFIG.INTERNAL_MODULE_PATTERNS) {
      if (pattern.pattern.test(packageName)) {
        // If we've detected the parent package, this is definitely an internal module
        if (detectedPackages.has(pattern.parent)) {
          return true;
        }
        // Even if parent not detected yet, it's likely internal
        // (parent might be detected later in the scan)
        return true;
      }
    }

    return false;
  }

  static stripQueryAndHash(value) {
    return value.split('#')[0].split('?')[0];
  }

  static isAliasPath(importPath) {
    if (!importPath) return false;

    const normalized = importPath.trim();
    const lower = normalized.toLowerCase();

    if (normalized.startsWith('/') && !normalized.startsWith('//')) return true;
    if (/^[a-z]:[\\/]/i.test(normalized) || normalized.startsWith('\\\\')) return true;

    for (const prefix of CONFIG.INTERNAL_ALIAS_PREFIXES) {
      if (lower.startsWith(prefix)) return true;
    }

    if (lower === '~' || lower.startsWith('~/')) return true;

    const parts = normalized.split('/');
    if (parts.length > 1) {
      const root = parts[0].toLowerCase();
      if (CONFIG.INTERNAL_ALIAS_ROOTS.includes(root)) return true;
    }

    return false;
  }

  static normalizePackageName(pkgName) {
    if (!pkgName) return null;

    let normalized = pkgName.trim();
    if (normalized.startsWith('@')) {
      const match = normalized.match(/^(@[^/]+)\/(.+)$/);
      if (!match) return null;
      const scope = match[1];
      let name = match[2];
      name = name.split('@')[0];
      normalized = `${scope}/${name}`;
    } else if (normalized.includes('@')) {
      normalized = normalized.split('@')[0];
    }

    if (CONFIG.NODE_BUILTINS.has(normalized)) return null;

    // npm package names are effectively lowercase; normalize early to reduce false negatives
    normalized = normalized.toLowerCase();

    if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(normalized)) return null;

    return normalized;
  }

  /**
   * Extract an npm package name from a source-map "sources" entry by looking for
   * a node_modules segment. This is much more reliable than treating the entire
   * path as an import specifier.
   */
  static extractFromNodeModulesPath(value) {
    if (!value || typeof value !== 'string') return null;

    let cleaned = value.trim();
    if (!cleaned) return null;

    cleaned = this.stripQueryAndHash(cleaned).replace(/\\/g, '/');
    const lower = cleaned.toLowerCase();

    const markers = ['node_modules/', '/~/'];
    let idx = -1;
    let markerLen = 0;
    let usedMarker = null;
    for (const m of markers) {
      const i = lower.lastIndexOf(m);
      if (i > idx) {
        idx = i;
        markerLen = m.length;
        usedMarker = m;
      }
    }
    if (idx === -1) return null;

    const rest = cleaned.slice(idx + markerLen);
    const parts = rest.split('/').filter(Boolean);
    if (parts.length === 0) return null;

    let pkg = parts[0];
    // In some frameworks, "~/" is an alias to the app root. Filter common app roots to reduce false positives.
    if (usedMarker === '/~/' && CONFIG.INTERNAL_ALIAS_ROOTS.includes(pkg.toLowerCase())) return null;
    if (pkg.startsWith('@')) {
      if (parts.length < 2) return null;
      pkg = `${parts[0]}/${parts[1]}`;
    }

    return this.normalizePackageName(pkg);
  }

  static extract(importPath) {
    if (!importPath || typeof importPath !== 'string') return null;

    let cleaned = importPath.trim();
    if (!cleaned) return null;

    cleaned = this.stripQueryAndHash(cleaned);

    if (this.isAliasPath(cleaned)) return null;

    // 1. Handle CDN URLs
    try {
      const url = new URL(cleaned, 'https://example.com'); // Base for relative URLs
      const hostname = url.hostname;

      if (hostname.includes('unpkg.com') || hostname.includes('jsdelivr.net') || hostname.includes('cdnjs.cloudflare.com')) {
        // unpkg.com/react@18.2.0/index.js -> react
        // cdn.jsdelivr.net/npm/react@18.2.0/index.js -> react
        // cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js -> react

        const pathParts = url.pathname.split('/').filter(p => p);

        // Handle jsdelivr /npm/ prefix
        if (hostname.includes('jsdelivr.net') && pathParts[0] === 'npm') {
          pathParts.shift();
        }
        // Handle cdnjs /ajax/libs/ prefix
        if (hostname.includes('cdnjs.cloudflare.com') && pathParts[0] === 'ajax' && pathParts[1] === 'libs') {
          return this.normalizePackageName(pathParts[2]); // cdnjs structure is usually /ajax/libs/<package>/...
        }

        if (pathParts.length === 0) return null;

        let pkgPart = pathParts[0];

        // Handle scoped packages in URL (e.g. @scope/pkg)
        if (pkgPart.startsWith('@') && pathParts.length > 1) {
          pkgPart = `${pathParts[0]}/${pathParts[1]}`;
        }

        return this.normalizePackageName(pkgPart);
      }
      // If it's an absolute web URL but NOT a known CDN, ignore it
      // This prevents false positives like 'connect.facebook.net' being treated as a package
      if (/^(https?:)?\/\//.test(cleaned)) {
        return null;
      }

    } catch (e) {
      // Not a URL, continue to standard extraction
    }

    // 2. Standard Import Path Cleaning
    cleaned = cleaned
      .replace(/^(https?:\/\/|node:|file:)/, '')
      .replace(/^(\.\.\/)*node_modules\//, '');

    if (cleaned.startsWith('.')) return null;
    if (cleaned.startsWith('/') && !cleaned.startsWith('//')) return null;
    if (this.isAliasPath(cleaned)) return null;

    const parts = cleaned.split('/');

    // Handle scoped packages (@org/package)
    let pkgName = parts[0];
    if (cleaned.startsWith('@')) {
      pkgName = parts.length > 1 ? `${parts[0]}/${parts[1]}` : null;
    }

    return this.normalizePackageName(pkgName);
  }
}

// ============================================================================
// WEB CRAWLER
// ============================================================================

class WebCrawler {
  constructor(baseUrl) {
    this.baseUrl = new URL(baseUrl);
    this.discoveredUrls = new Set();
    this.scannedUrls = new Set();
  }

  async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
      // NOTE: default cache mode ('default') lets the browser reuse cached responses
      // across the same scanning session. Previously we used 'force-cache' which
      // actively *throws* if the response cannot be stored (e.g. opaque redirects,
      // 404s on small caches), causing whole crawler runs to fail.
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        cache: options.cache || 'default'
      });
      clearTimeout(timeout);
      return response;
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  }

  normalizeUrl(url) {
    try {
      return new URL(url, this.baseUrl).href;
    } catch {
      return null;
    }
  }

  async discoverUrlsFromHtml(html) {
    const urls = new Set();
    const patterns = [
      /<script[^>]+src=["']([^"']+)["']/gi,
      /<link[^>]+href=["']([^"']+)["'][^>]*>/gi,
      /["']([^"']*(?:manifest|asset-manifest)\.json)["']/gi
    ];

    for (const regex of patterns) {
      let match;
      while ((match = regex.exec(html)) !== null) {
        const url = this.normalizeUrl(match[1]);
        if (url) {
          // Allow all scripts, including external CDNs
          urls.add(url);
        }
      }
    }
    return Array.from(urls);
  }

  async discoverAllUrls() {
    Logger.debug('Starting URL discovery...');

    // 1. Initial Page
    const pageHtml = document.documentElement.outerHTML;
    (await this.discoverUrlsFromHtml(pageHtml)).forEach(u => this.discoveredUrls.add(u));

    // 2. Performance Entries
    performance.getEntriesByType('resource').forEach(r => {
      if (r.initiatorType === 'script' || r.name.match(/\.(js|mjs|jsx|ts|tsx)$/)) {
        // Allow all script resources
        this.discoveredUrls.add(r.name);
      }
    });

    // 3. Crawl Common Directories (Parallel)
    const dirPromises = CONFIG.COMMON_DIRS.map(async dir => {
      try {
        const response = await this.fetchWithTimeout(dir);
        if (response.ok) {
          const text = await response.text();
          const matches = text.match(/href=["']([^"']+\.(js|json))["']/g);
          if (matches) {
            matches.forEach(m => {
              const u = this.normalizeUrl(dir + m.slice(6, -1));
              if (u) this.discoveredUrls.add(u);
            });
          }
        }
      } catch (e) { /* ignore */ }
    });
    await Promise.all(dirPromises);

    const discovered = Array.from(this.discoveredUrls);
    if (discovered.length > CONFIG.MAX_DISCOVERED_URLS) {
      Logger.debug(`Discovered ${discovered.length} URLs, limiting to ${CONFIG.MAX_DISCOVERED_URLS} to avoid scan stalls`);
      return discovered.slice(0, CONFIG.MAX_DISCOVERED_URLS);
    }

    Logger.debug(`Discovered ${discovered.length} URLs`);
    return discovered;
  }
}

// ============================================================================
// PACKAGE SCANNER
// ============================================================================

class PackageScanner {
  constructor() {
    this.packages = new Map();
    this.npmPackageNames = new Set();
    this.rateLimiter = new RateLimiter(CONFIG.API_RATE_LIMIT, CONFIG.API_WINDOW);
    this.cache = new Map();
    this.scannedFiles = 0;
    this.totalFiles = 0;
    // Targets discovered during scan-content (service workers, webpack chunks, JSON URLs).
    // They are processed in a second-pass crawl at the end of scanAllDiscoveredFiles.
    this.additionalCrawlTargets = [];
  }

  async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
      return await fetch(url, {
        ...options,
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  addPackage(ecosystem, packageName, source) {
    if (!ecosystem || !packageName) return;

    // Normalize npm names to avoid case-sensitive registry lookups causing false results.
    if (ecosystem === 'npm' && typeof packageName === 'string') {
      packageName = packageName.trim().toLowerCase();
    }

    // Drop strings that are clearly not package specifiers (HTML fragments, JSON keys, base64 blobs).
    if (typeof packageName === 'string' && (
      packageName.endsWith('.html') ||
      packageName.endsWith('.htm') ||
      packageName.includes('</') ||
      packageName.startsWith('{') ||
      packageName.startsWith('[') ||
      packageName.startsWith('<') ||
      packageName.includes(';base64,') ||
      packageName.includes('http://') ||
      packageName.includes('https://') ||
      packageName.includes('\n') ||
      packageName.length > 120
    )) {
      return;
    }

    // Filter out internal modules to prevent false positives
    if (ecosystem === 'npm') {
      if (PackageNameExtractor.isInternalModule(packageName, this.npmPackageNames)) {
        Logger.debug(`Skipping internal module: ${packageName}`);
        return;
      }
      this.npmPackageNames.add(packageName);
    }

    const key = `${ecosystem}:${packageName}`;
    if (!this.packages.has(key)) {
      this.packages.set(key, { ecosystem, name: packageName, sources: new Set() });
    }
    this.packages.get(key).sources.add(source);
  }

  async scanPageSource() {
    const scripts = Array.from(document.scripts || []);
    scripts.forEach(script => {
      const type = (script.type || '').trim().toLowerCase();
      const isJsType = !type || type === 'text/javascript' || type === 'application/javascript' || type === 'module' || type === 'text/ecmascript' || type === 'application/ecmascript';
      const content = script.textContent || '';
      if (!content.trim()) return;

      // Import map declarations are an explicit, golden dependency surface.
      // Many modern apps declare bare specifiers (e.g. "react") here without going through require/import.
      if (type === 'importmap') {
        this.extractImportmapPackages(content, 'Import Map');
        return;
      }

      // JSON-LD / inline JSON occasionally leak asset URLs we can crawl.
      if (type === 'application/ld+json' || type === 'application/json' || type === 'application/ld+json; charset=utf-8') {
        this.extractInlineJsonUrls(content, script.src || 'Inline JSON');
        return;
      }

      if (!isJsType) return;
      if (script.src) return; // External scripts are handled by the crawler

      this.scanContent(content, 'Inline Script');
    });
  }

  /**
   * Parse an inline import map and queue its declared packages for analysis.
   * Filters out non-bare specifiers (paths, URLs, relative references).
   */
  extractImportmapPackages(content, source) {
    try {
      const json = JSON.parse(content);
      const imports = (json && typeof json === 'object' && json.imports) || {};
      let added = 0;
      Object.keys(imports).forEach((specifier) => {
        if (!specifier) return;
        // Drop scope mappings and obvious non-package keys.
        if (specifier.endsWith('/') || specifier.includes('://') || specifier.startsWith('.') || specifier.startsWith('/')) return;
        const pkg = PackageNameExtractor.extract(specifier);
        if (pkg) {
          this.addPackage('npm', pkg, source);
          added += 1;
        }
      });
      if (added > 0) Logger.debug(`Import map: added ${added} top-level packages.`);
    } catch (e) {
      // Malformed import map is common on live sites; fail silently.
    }
  }

  /**
   * Surface any http(s) URLs from inline JSON-LD / application/json blocks
   * so they get crawled alongside other resources.
   */
  extractInlineJsonUrls(content, source) {
    const matches = content.match(/https?:\/\/[^\s"']+/g);
    if (!matches) return;
    matches.forEach((url) => {
      const normalized = url.replace(/[",\]\}]+$/g, '');
      try {
        const resolved = new URL(normalized);
        if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return;
        this.additionalCrawlTargets.push(resolved.href);
        Logger.debug(`JSON ${source} URL: ${resolved.href}`);
      } catch (e) { /* ignore */ }
    });
  }

  scanContent(content, source) {
    // Strip comments and TS type-only imports BEFORE matching. This is the single largest
    // source of false positives in real-world bundles (documentation, banners, type defs).
    const clean = PackageNameExtractor.stripNonCode(content);

    // Anchored patterns: leading @-lookbehind avoids matching CSS @import / @require.
    // Word-boundary \b prevents matches inside identifiers like "reimports".
    // Negative lookaheads prevent matching TS type-only imports/exports.
    const patterns = [
      /(?<!@)\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /(?<!@)\bimport\s+(?!type\b).*?\s+from\s+['"]([^'"]+)['"]/g,
      /(?<!@)\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /(?<!@)\bexport\s+(?!type\b).*?\s+from\s+['"]([^'"]+)['"]/g,
      // AMD / RequireJS
      /(?<!@)\bdefine\s*\(\s*\[\s*['"]([^'"]+)['"]/g,
      // Webpack / Bundlers
      /(?<!@)\b__webpack_require__\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /(?<!@)\brequire\.ensure\s*\(\s*\[\s*['"]([^'"]+)['"]/g,
      // SystemJS
      /(?<!@)\bSystem\.import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(clean)) !== null) {
        if (match[1]) {
          const pkg = PackageNameExtractor.extract(match[1]);
          this.addPackage('npm', pkg, source);
        }
      }
    }

    // Service worker registrations: queue the script URL for second-pass crawl.
    const swPattern = /navigator\.serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]/g;
    let swMatch;
    while ((swMatch = swPattern.exec(content)) !== null) {
      if (swMatch[1]) {
        try {
          const absolute = new URL(swMatch[1], location.href).href;
          this.additionalCrawlTargets.push(absolute);
        } catch (e) { /* ignore */ }
      }
    }

    // Webpack runtime chunk URL pattern: __webpack_require__.p + "<chunk>.js".
    // We surface these so the crawler can fetch them in a follow-up pass.
    const wpPattern = /__webpack_require__\.p\s*\+\s*['"]([^'"]+\.js)['"]/g;
    let wpMatch;
    while ((wpMatch = wpPattern.exec(content)) !== null) {
      if (wpMatch[1]) {
        try {
          const absolute = new URL(wpMatch[1], location.href).href;
          this.additionalCrawlTargets.push(absolute);
        } catch (e) { /* ignore */ }
      }
    }
  }

  async scanAllDiscoveredFiles(urls) {
    this.totalFiles = urls.length;
    this.scannedFiles = 0;

    // 1. Check if the URLs themselves are packages (CDNs)
    this.scanUrls(urls);

    // 2. Process in chunks to avoid overwhelming the browser
    const chunkSize = 5;
    for (let i = 0; i < urls.length; i += chunkSize) {
      const chunk = urls.slice(i, i + chunkSize);
      await Promise.all(chunk.map(url => this.scanJsFile(url)));
    }

    // 3. Second-pass deep crawl is gated by the deepCrawl setting (default on).
    // Targets come from import maps, JSON URLs, service workers, and webpack chunks.
    if (scanState.deepCrawl === false) {
      Logger.debug('deepCrawl disabled; skipping second-pass scan.');
      return;
    }
    const extraTargets = Array.from(new Set(this.additionalCrawlTargets || []))
      .filter((u) => urls.indexOf(u) === -1)
      .slice(0, CONFIG.MAX_DEEP_TARGETS || 24);

    if (extraTargets.length > 0) {
      Logger.debug(`Deep-scan pass: ${extraTargets.length} extra targets`);
      this.totalFiles += extraTargets.length;
      for (let i = 0; i < extraTargets.length; i += chunkSize) {
        const chunk = extraTargets.slice(i, i + chunkSize);
        await Promise.all(chunk.map(url => this.scanJsFile(url)));
      }
    }
  }

  scanUrls(urls) {
    urls.forEach(url => {
      const pkg = PackageNameExtractor.extract(url);
      if (pkg) {
        this.addPackage('npm', pkg, `CDN/URL: ${url}`);
      }
    });
  }

  async scanJsFile(url) {
    try {
      // Default cache mode so repeated fetches of the same bundle within a session
      // hit cache. Using 'no-cache' here triggered revalidation on every script.
      const response = await this.fetchWithTimeout(url, { cache: 'default' });
      if (!response.ok) return;
      const content = await response.text();
      this.scanContent(content, url);

      // Check for source map
      const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL=(.+\.map)/);
      if (mapMatch) {
        const mapUrl = new URL(mapMatch[1].trim(), url).href;
        await this.scanSourceMap(mapUrl);
      }
    } catch (e) {
      // ignore
    } finally {
      this.scannedFiles++;
    }
  }

  async scanSourceMap(url) {
    try {
      const response = await this.fetchWithTimeout(url, { cache: 'default' });
      if (!response.ok) return;
      const map = await response.json();
      if (map.sources) {
        map.sources.forEach(s => {
          const pkg = PackageNameExtractor.extractFromNodeModulesPath(s);
          this.addPackage('npm', pkg, `Source Map: ${url}`);
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Optimized Directory Brute-Force
  async checkExposedFiles() {
    Logger.debug('Checking for exposed files (Concurrent Mode)...');
    const exposedFiles = [];

    const basePaths = new Set(['/']);
    const currentPath = window.location.pathname || '/';
    const baseDir = currentPath.endsWith('/') ? currentPath : currentPath.slice(0, currentPath.lastIndexOf('/') + 1);
    if (baseDir && baseDir !== '/') {
      basePaths.add(baseDir);
    }

    const baselineContent = new Map();
    for (const basePath of basePaths) {
      try {
        const res = await this.fetchWithTimeout(basePath, { cache: 'default' });
        baselineContent.set(basePath, res.ok ? await res.text() : '');
      } catch (e) {
        baselineContent.set(basePath, '');
      }
    }

    // Helper to check a single file
    const checkFile = async (path, basePath) => {
      try {
        // 1. Fast HEAD check ('reload' so 404s aren't served from cache during rescan)
        let headRes = null;
        try {
          headRes = await this.fetchWithTimeout(path, { method: 'HEAD', cache: 'reload' });
        } catch (e) {
          headRes = null;
        }

        const allowGet = !headRes || headRes.ok || headRes.status === 405 || headRes.status === 501;
        if (!allowGet) return;

        // 2. Validation GET (prevent false positives from custom 404s)
        // 'reload' forces a fresh fetch each time to defeat soft-cache based SPA fallbacks
        const getRes = await this.fetchWithTimeout(path, {
          method: 'GET',
          cache: 'reload',
          headers: { 'Range': 'bytes=0-512' }
        });

        if (getRes.ok) {
          const text = await getRes.text();

          // Soft 404 Check: Compare with base content
          // If the content is identical or extremely similar to the base, it's likely a SPA fallback
          const baseContent = baselineContent.get(basePath) || '';
          if (baseContent && (text === baseContent.slice(0, text.length) || text.includes('<!DOCTYPE html>'))) {
            // Double check if it's NOT an expected HTML file
            if (!path.endsWith('.html')) {
              return; // False positive: Soft 404
            }
          }

          const filename = path.split('/').pop() || 'node_modules';
          const pattern = CONFIG.CONFIG_PATTERNS[filename];

          // If we have a pattern, enforce it
          if (pattern) {
            if (!pattern.test(text)) {
              return; // False positive: Content doesn't match expected format
            }
          } else {
            // Fallback for files without specific patterns
            const contentType = (getRes.headers.get('content-type') || '').toLowerCase();

            // STRICT CHECK: Reject if Content-Type is HTML
            if (contentType.includes('text/html')) {
              return; // False positive
            }

            // STRICT CHECK: Reject if content looks like HTML
            if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')) {
              return; // False positive
            }

            const isHtml = contentType.includes('text/html') || text.includes('<!DOCTYPE html>');
            const expectedJson = path.endsWith('.json') || path.endsWith('rc');

            if (expectedJson && isHtml) {
              return; // False positive
            }
          }

          let risk = 'LOW';
          if (filename.startsWith('.env') || filename === '.npmrc') risk = 'HIGH';
          else if (filename.includes('lock') || filename === 'package.json' || filename === 'npm-shrinkwrap.json') risk = 'MEDIUM';

          exposedFiles.push({
            path,
            risk,
            status: getRes.status,
            contentType: getRes.headers.get('content-type')
          });

          await this.parseDependencyFile(path);
        }
      } catch (e) {
        // Ignore network errors (file not found)
      }
    };

    // Run checks in parallel with concurrency limit
    const pool = [];
    const limit = CONFIG.MAX_CONCURRENT_SCANS;

    const candidatePaths = [];
    for (const basePath of basePaths) {
      const prefix = basePath === '/' ? '' : basePath.replace(/\/$/, '');
      for (const path of CONFIG.CONFIG_FILES) {
        candidatePaths.push({ path: `${prefix}${path}`, basePath });
      }
    }

    for (const { path, basePath } of candidatePaths) {
      const p = checkFile(path, basePath).then(() => {
        pool.splice(pool.indexOf(p), 1);
      });
      pool.push(p);
      if (pool.length >= limit) await Promise.race(pool);
    }
    await Promise.all(pool);

    return exposedFiles;
  }

  async parsePackageJson(packagePath = '/package.json') {
    try {
      // 'reload' bypasses cache so each scan sees the current manifest even if
      // a stale cached version is still in the HTTP cache. Previously 'no-cache'
      // forced revalidation per call without ever returning a fresh body when
      // the upstream sent 304s.
      const res = await this.fetchWithTimeout(packagePath, { cache: 'reload' });
      const text = await res.text();
      this.parsePackageJsonContent(text, packagePath);
    } catch (e) { /* ignore */ }
  }

  parsePackageJsonContent(content, source) {
    try {
      const json = JSON.parse(content);
      ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].forEach(t => {
        if (json[t]) Object.keys(json[t]).forEach(d => this.addPackage('npm', d, source));
      });
    } catch (e) { /* ignore */ }
  }

  parseRequirementsTxt(content, source) {
    const lines = (content || '').split(/\r?\n/);
    lines.forEach(line => {
      const stripped = line.trim();
      if (!stripped || stripped.startsWith('#')) return;
      if (stripped.startsWith('-')) return;
      if (stripped.includes('://') || stripped.startsWith('git+')) return;
      if (stripped.startsWith('-e ') || stripped.startsWith('--') || stripped.startsWith('-r ') || stripped.startsWith('-c ')) return;
      let name = stripped.split(/[\s<=>~!]/)[0];
      name = name.split('[')[0];
      if (stripped.includes('egg=')) {
        const egg = stripped.split('egg=')[1];
        if (egg) name = egg;
      }
      if (name) this.addPackage('pypi', name, source);
    });
  }

  parsePipfile(content, source) {
    let inPackages = false;
    let inDevPackages = false;
    const lines = (content || '').split(/\r?\n/);
    for (const line of lines) {
      const stripped = line.trim();
      if (!stripped || stripped.startsWith('#')) continue;
      if (stripped.startsWith('[') && stripped.endsWith(']')) {
        const section = stripped.slice(1, -1).toLowerCase();
        inPackages = section === 'packages';
        inDevPackages = section === 'dev-packages';
        continue;
      }
      if ((inPackages || inDevPackages) && stripped.includes('=')) {
        const name = stripped.split('=')[0].trim().replace(/^["']|["']$/g, '');
        const value = stripped.split('=')[1].trim();
        if (!this.isPypiValueAllowed(value)) continue;
        if (name) this.addPackage('pypi', name, source);
      }
    }
  }

  parsePipfileLock(content, source) {
    try {
      const json = JSON.parse(content);
      ['default', 'develop'].forEach(section => {
        const deps = json[section] || {};
        Object.keys(deps).forEach(name => {
          const meta = deps[name];
          if (this.isPypiValueAllowed(meta)) {
            this.addPackage('pypi', name, source);
          }
        });
      });
    } catch (e) { /* ignore */ }
  }

  isPypiValueAllowed(value) {
    if (value == null) return true;
    if (typeof value === 'object') {
      const keys = Object.keys(value);
      for (const key of ['path', 'file', 'git', 'editable', 'url']) {
        if (keys.includes(key)) return false;
      }
      return true;
    }
    const text = String(value).toLowerCase();
    if (text.startsWith('http://') || text.startsWith('https://') || text.startsWith('git+') || text.startsWith('git://')) return false;
    if (text.startsWith('file:') || text.startsWith('link:') || text.startsWith('workspace:')) return false;
    return true;
  }

  parseGemfile(content, source) {
    const regex = /^\s*gem\s+['"]([^'"]+)['"]/gm;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const name = match[1];
      if (name) this.addPackage('rubygems', name, source);
    }
  }

  parseComposerJson(content, source) {
    try {
      const json = JSON.parse(content);
      ['require', 'require-dev'].forEach(key => {
        const reqs = json[key] || {};
        Object.keys(reqs).forEach(name => {
          if (!name || name === 'php') return;
          if (name.startsWith('ext-') || name.startsWith('lib-')) return;
          if (name.includes('/')) this.addPackage('composer', name, source);
        });
      });
    } catch (e) { /* ignore */ }
  }

  parsePomXml(content, source) {
    const regex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const block = match[1];
      const group = /<groupId>(.*?)<\/groupId>/.exec(block);
      const artifact = /<artifactId>(.*?)<\/artifactId>/.exec(block);
      if (group && artifact) {
        const name = `${group[1].trim()}:${artifact[1].trim()}`;
        if (!name.includes('${')) this.addPackage('maven', name, source);
      }
    }
  }

  parseGradle(content, source) {
    const regex = /['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^'"]+['"]/g;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const name = `${match[1]}:${match[2]}`;
      if (!name.includes('${')) this.addPackage('maven', name, source);
    }
  }

  parseNuget(content, source) {
    const refs = [];
    const regex1 = /PackageReference\s+Include="([^"]+)"/g;
    const regex2 = /<package\s+id="([^"]+)"/g;
    let match;
    while ((match = regex1.exec(content || '')) !== null) refs.push(match[1]);
    while ((match = regex2.exec(content || '')) !== null) refs.push(match[1]);
    refs.forEach(name => {
      if (name) this.addPackage('nuget', name, source);
    });
  }

  parseGoMod(content, source) {
    const lines = (content || '').split(/\r?\n/);
    let inRequire = false;
    for (const line of lines) {
      const stripped = line.trim();
      if (stripped.startsWith('require (')) {
        inRequire = true;
        continue;
      }
      if (inRequire && stripped === ')') {
        inRequire = false;
        continue;
      }
      if (stripped.startsWith('require ')) {
        const parts = stripped.replace(/^require\s+/, '').trim().split(/\s+/);
        if (parts[0]) this.addPackage('golang', parts[0], source);
      } else if (inRequire) {
        const parts = stripped.split(/\s+/);
        if (parts[0]) this.addPackage('golang', parts[0], source);
      }
    }
  }

  parseCargoToml(content, source) {
    const lines = (content || '').split(/\r?\n/);
    let inDeps = false;
    for (const line of lines) {
      const stripped = line.trim();
      if (stripped.startsWith('[') && stripped.endsWith(']')) {
        const section = stripped.slice(1, -1);
        inDeps = ['dependencies', 'dev-dependencies', 'build-dependencies'].includes(section);
        continue;
      }
      if (inDeps && stripped.includes('=') && !stripped.startsWith('#')) {
        const name = stripped.split('=')[0].trim();
        const value = stripped.split('=')[1].trim();
        if (value.includes('path =') || value.includes('git =')) continue;
        if (name) this.addPackage('crates', name, source);
      }
    }
  }

  async parseDependencyFile(path) {
    const lower = path.toLowerCase();
    try {
      const res = await this.fetchWithTimeout(path, { cache: 'reload' });
      if (!res.ok) return;
      const content = await res.text();
      if (lower.endsWith('package.json')) this.parsePackageJsonContent(content, path);
      else if (lower.endsWith('requirements.txt')) this.parseRequirementsTxt(content, path);
      else if (lower.endsWith('pipfile')) this.parsePipfile(content, path);
      else if (lower.endsWith('pipfile.lock')) this.parsePipfileLock(content, path);
      else if (lower.endsWith('gemfile')) this.parseGemfile(content, path);
      else if (lower.endsWith('composer.json')) this.parseComposerJson(content, path);
      else if (lower.endsWith('pom.xml')) this.parsePomXml(content, path);
      else if (lower.endsWith('build.gradle') || lower.endsWith('build.gradle.kts')) this.parseGradle(content, path);
      else if (lower.endsWith('packages.config') || lower.endsWith('.csproj')) this.parseNuget(content, path);
      else if (lower.endsWith('go.mod')) this.parseGoMod(content, path);
      else if (lower.endsWith('cargo.toml')) this.parseCargoToml(content, path);
    } catch (e) { /* ignore */ }
  }

  async analyzePackages(onUpdate, options = {}) {
    const maxPackages = Number.isFinite(Number(options.maxPackages))
      ? Math.max(0, Number(options.maxPackages))
      : this.packages.size;
    const packageList = Array.from(this.packages.values()).slice(0, maxPackages);

    Logger.debug(`Analyzing ${packageList.length}/${this.packages.size} packages...`);
    const results = [];

    for (const pkg of packageList) {
      results.push(await this.analyzePackage(pkg.ecosystem, pkg.name, Array.from(pkg.sources)));
      if (onUpdate) onUpdate(results);
    }
    return results;
  }

  async analyzePackage(ecosystem, name, sources) {
    // Content-script side cache. Background service worker has its own TTL cache.
    const cacheKey = `${ecosystem}:${name}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
      return { ...cached.data, sources, ecosystem };
    }

    await this.rateLimiter.waitForSlot();

    // Forward user's OSV-lookup setting to background so they can opt out.
    // Settings live in chrome.storage.sync (matching the rest of the extension settings).
    let osvLookup = true;
    try {
      const stored = await chrome.storage.sync.get({ osvLookup: true });
      if (typeof stored.osvLookup === 'boolean') osvLookup = stored.osvLookup;
    } catch (e) { /* storage may be unavailable */ }

    try {
      // Delegate to background script to bypass CSP/CORS
      const result = await Promise.race([
        chrome.runtime.sendMessage({
          action: 'analyzePackage',
          ecosystem,
          name,
          sources,
          options: { osvLookup }
        }),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Package analysis timed out')), CONFIG.REQUEST_TIMEOUT + 2000);
        })
      ]);

      if (result.error) {
        return { name, ecosystem, error: result.error, sources };
      }

      this.cacheResult(cacheKey, result);
      return { ...result, ecosystem };

    } catch (e) {
      return { name, ecosystem, error: e.message, sources };
    }
  }

  async fetchDownloads(name) {
    try {
      await this.rateLimiter.waitForSlot();
      const res = await this.fetchWithTimeout(`https://api.npmjs.org/downloads/point/last-week/${name}`);
      if (res.ok) {
        const data = await res.json();
        return data.downloads;
      }
    } catch (e) { return 0; }
    return 0;
  }

  assessRisk(info, downloads) {
    const reasons = [];
    let suspicious = false;
    let level = 'LOW';

    if (downloads < CONFIG.MIN_DOWNLOADS_SUSPICIOUS && !info.repository) {
      suspicious = true;
      level = 'HIGH';
      reasons.push('Low downloads + No Repo');
    }

    // Typosquatting check
    if (/[0-9]{3,}|[il1][o0]/.test(info.name)) {
      suspicious = true;
      level = 'MEDIUM';
      reasons.push('Suspicious name pattern');
    }

    return { suspicious, riskLevel: suspicious ? level : 'LOW', riskReasons: reasons };
  }

  cacheResult(name, data) {
    this.cache.set(name, { data, timestamp: Date.now() });
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

let scanner = new PackageScanner();
let crawler = new WebCrawler(window.location.href);
let scanSessionId = 0;

// State Management
let scanState = {
  scanning: false,
  complete: false,
  packages: [],
  exposedFiles: [],
  error: null,
  url: window.location.href,
  partial: false,
  enabled: true, // Extension enabled by default
  // Mirrors the chrome.storage.sync.deepCrawl setting so the scanner honours the popup toggle.
  deepCrawl: true,
  // Stage progress (0–100 + text). The popup renders a progress bar from this.
  stage: { progress: 0, text: 'Initializing…' }
};

async function runStageWithTimeout(stageName, work, fallbackValue, timeoutMs = CONFIG.STAGE_TIMEOUT) {
  let timerId;
  const timeoutPromise = new Promise((resolve) => {
    timerId = setTimeout(() => {
      Logger.warn(`${stageName} timed out after ${timeoutMs}ms; continuing with partial data.`);
      resolve(fallbackValue);
    }, timeoutMs);
  });

  try {
    const result = await Promise.race([Promise.resolve().then(work), timeoutPromise]);
    clearTimeout(timerId);
    return result;
  } catch (error) {
    clearTimeout(timerId);
    Logger.warn(`${stageName} failed; continuing with partial data.`, error);
    return fallbackValue;
  }
}

// Auto-start scan
async function runAutoScan() {
  const sessionId = ++scanSessionId;
  const scanStartedAt = Date.now();
  const isOutOfTime = () => (Date.now() - scanStartedAt) >= CONFIG.TOTAL_SCAN_TIMEOUT;

  // Check if extension is enabled and honour the autoScan + deepCrawl toggles from
  // chrome.storage.sync (set by the popup settings panel).
  const [local, sync] = await Promise.all([
    chrome.storage.local.get(['extensionEnabled']),
    chrome.storage.sync.get({ autoScan: true, deepCrawl: true })
  ]);
  const isEnabled = local.extensionEnabled !== false;
  const autoScan = sync.autoScan !== false;
  const deepCrawl = sync.deepCrawl !== false;
  scanState.enabled = isEnabled;
  scanState.deepCrawl = deepCrawl;

  if (!isEnabled) {
    Logger.debug('Extension is disabled. Scan aborted.');
    return;
  }
  if (!autoScan) {
    Logger.debug('autoScan is disabled. Scan aborted.');
    return;
  }

  if (scanState.scanning || scanState.complete) return;

  scanState.scanning = true;
  scanState.complete = false;
  scanState.error = null;
  scanState.url = window.location.href;
  scanState.partial = false;
  scanState.stage = { progress: 5, text: 'Starting scan…' };
  Logger.debug('Auto-scan initiated...');

  const finalizeScan = (partial = false) => {
    if (sessionId !== scanSessionId) return;
    scanState.scanning = false;
    scanState.complete = true;
    scanState.partial = partial;
  };

  try {
    // 1. Scan Page Source
    scanState.stage = { progress: 15, text: 'Crawling page source…' };
    await runStageWithTimeout('Scan page source', () => scanner.scanPageSource(), null);
    if (sessionId !== scanSessionId) return;
    if (isOutOfTime()) {
      finalizeScan(true);
      return;
    }

    // 2. Crawl & Scan Scripts
    scanState.stage = { progress: 30, text: 'Discovering URLs…' };
    const urls = await runStageWithTimeout('Discover URLs', () => crawler.discoverAllUrls(), []);
    scanState.stage = { progress: 50, text: `Scanning ${urls.length} script(s)…` };
    await runStageWithTimeout('Scan discovered files', () => scanner.scanAllDiscoveredFiles(urls), null);
    if (sessionId !== scanSessionId) return;
    if (isOutOfTime()) {
      finalizeScan(true);
      return;
    }

    // 3. Check Exposed Files
    scanState.stage = { progress: 70, text: 'Checking exposed files…' };
    const exposedFiles = await runStageWithTimeout('Check exposed files', () => scanner.checkExposedFiles(), []);
    if (sessionId !== scanSessionId) return;
    scanState.exposedFiles = exposedFiles;
    if (isOutOfTime()) {
      finalizeScan(true);
      return;
    }

    // 4. Analyze Packages (incremental)
    const packageCount = scanner.packages.size;
    scanState.stage = { progress: 85, text: `Analyzing ${packageCount} package(s)…` };
    const packageResults = await runStageWithTimeout(
      'Analyze packages',
      () => scanner.analyzePackages((partial) => {
        if (sessionId !== scanSessionId) return;
        scanState.packages = partial.slice();
        const suspiciousPackages = scanState.packages.filter(p => p.suspicious);
        if (suspiciousPackages.length > 0 || scanState.exposedFiles.length > 0) {
          chrome.runtime.sendMessage({
            action: 'notifyRisks',
            suspiciousPackages,
            exposedFiles: scanState.exposedFiles
          });
        }
      }, { maxPackages: CONFIG.MAX_ANALYSIS_PACKAGES }),
      scanState.packages.slice(),
      Math.max(CONFIG.STAGE_TIMEOUT, 22000)
    );
    if (sessionId !== scanSessionId) return;
    const suspiciousPackages = packageResults.filter(p => p.suspicious);

    // Update State
    scanState.packages = packageResults;
    scanState.exposedFiles = exposedFiles;
    finalizeScan(isOutOfTime());

    // 5. Report Results (Optional: Badge/Notification)
    // 5. Report Results (Optional: Badge/Notification)
    if (suspiciousPackages.length > 0 || exposedFiles.length > 0) {
      chrome.runtime.sendMessage({
        action: 'notifyRisks',
        suspiciousPackages,
        exposedFiles
      });
    }

  } catch (e) {
    if (sessionId !== scanSessionId) return;
    scanState.error = null;
    finalizeScan(true);
    Logger.error('Scan failed:', e);
  }
}  function resetForRescan() {
  scanSessionId += 1;
  scanner = new PackageScanner();
  crawler = new WebCrawler(window.location.href);

  scanState.scanning = false;
  scanState.complete = false;
  scanState.packages = [];
  scanState.exposedFiles = [];
  scanState.error = null;
  scanState.partial = false;
  scanState.url = window.location.href;
  scanState.stage = { progress: 0, text: 'Initializing…' };
  // deepCrawl is preserved across rescan (it's a per-page-load setting from storage).
}

// Start immediately (with slight delay for DOM)
setTimeout(runAutoScan, 1000);

// Listen for messages from Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getScanStatus' || request.action === 'startScan') {
    // Return current state immediately
    sendResponse(scanState);
    return true;
  }

  if (request.action === 'forceRescan') {
    resetForRescan();
    runAutoScan().catch((error) => {
      Logger.error('Force rescan failed:', error);
    });
    sendResponse({ success: true, started: true });
    return true;
  }

  if (request.action === 'toggleExtension') {
    const isEnabled = request.enabled;
    scanState.enabled = isEnabled;

    Logger.debug(`Extension ${isEnabled ? 'ENABLED' : 'DISABLED'}`);

    // If enabled and not yet scanned, start scan
    if (isEnabled && !scanState.complete && !scanState.scanning) {
      runAutoScan();
    }

    // If disabled, clear results
    if (!isEnabled) {
      scanSessionId += 1;
      scanState.packages = [];
      scanState.exposedFiles = [];
      scanState.complete = false;
      scanState.scanning = false;
      scanState.error = null;
      scanState.partial = false;
    }

    sendResponse({ success: true, enabled: isEnabled });
    return true;
  }
});
