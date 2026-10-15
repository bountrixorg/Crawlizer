/**
 * Katana Supply Chain Scanner - Pattern-Based Multi-Ecosystem Dependency & Vulnerability Engine
 * Scans HTML, DOM Scripts, JS Bundles, CSS, JSON Manifests, and Source Maps for package references.
 * Pattern-based architecture matching KatanaSecretScanner with integrated OSV.dev CVE advisories
 * and dependency confusion detection.
 */

// ============================================================================
// LRU CACHE UTILITY
// ============================================================================
class SupplyChainLRUCache {
  constructor(maxSize = 512) {
    this.maxSize = Math.max(1, Number(maxSize) || 512);
    this.map = new Map();
  }

  get(key) {
    if (!this.map.has(key)) return undefined;
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

  clear() {
    this.map.clear();
  }
}

// ============================================================================
// PATTERN RULES & DICTIONARIES
// ============================================================================

// Node.js standard built-in modules & CommonJS/AMD pseudo-modules to ignore
const NODE_BUILTINS = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'fs/promises', 'http', 'http2', 'https', 'inspector',
  'module', 'net', 'os', 'path', 'path/posix', 'path/win32', 'perf_hooks',
  'process', 'punycode', 'querystring', 'readline', 'repl', 'stream',
  'stream/promises', 'stream/consumers', 'stream/web', 'string_decoder',
  'sys', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
  'url', 'util', 'util/types', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
  // CommonJS, AMD, bundler pseudo-modules & JS globals to ignore
  'exports', 'require', '__proto__', 'prototype', 'global', 'globalthis',
  'window', 'document', 'self', 'this', 'default', '__esmodule',
  'undefined', 'null', 'nan', 'arguments', 'caller', 'callee'
]);

// Relative path prefixes and framework aliases to ignore
const LOCAL_PATH_PREFIXES = [
  './', '../', '/', '\\', '@/', '~/', '~~/'
];

// Common internal root directory names
const INTERNAL_ROOTS = new Set([
  'src', 'app', 'apps', 'components', 'component', 'pages', 'layouts', 'views',
  'hooks', 'utils', 'lib', 'libs', 'services', 'service', 'store', 'stores',
  'state', 'modules', 'assets', 'styles', 'css', 'scss', 'sass', 'less',
  'images', 'img', 'fonts', 'locales', 'i18n', 'types', 'constants',
  'config', 'configs', 'public', 'static', 'fixtures', 'tests', '__tests__'
]);

// Internal module patterns that are sub-components of parent packages
const INTERNAL_MODULE_PATTERNS = [
  { parent: 'prismjs', pattern: /^prism-[a-z]+$/ },
  { parent: 'highlight.js', pattern: /^highlight\.js\/lib\/languages\// },
  { parent: 'monaco-editor', pattern: /^monaco-editor\/esm\// },
  { parent: 'codemirror', pattern: /^codemirror\/(?:mode|addon)\// },
  { parent: 'ace-builds', pattern: /^ace\/(?:mode|theme)\// },
  { parent: '@babel/runtime', pattern: /^@babel\/runtime\/(?:helpers|core-js|regenerator)/ },
  { parent: 'rxjs', pattern: /^rxjs\/(?:internal|operators|testing|ajax|fetch|webSocket|dist)/ },
  { parent: 'swiper', pattern: /^swiper\/(?:components|modules|core|shared|element|vue)/ },
  { parent: 'lodash', pattern: /^lodash\/[a-zA-Z0-9_]+$/ },
  { parent: 'lodash-es', pattern: /^lodash-es\/.+$/ },
  { parent: 'antd', pattern: /^antd\/(?:es|lib|dist)\// },
  { parent: '@mui/material', pattern: /^@mui\/material\/(?:styles|colors|utils|internal|esm|lab)/ },
  { parent: '@mui/system', pattern: /^@mui\/system\/(?:styles|colors|utils|esm)/ },
  { parent: 'date-fns', pattern: /^date-fns\/(?:locale|esm)/ },
  { parent: 'vue', pattern: /^vue\/(?:dist|esm|server|shared|compiler-sfc)/ },
  { parent: 'react-dom', pattern: /^react-dom\/(?:client|server|test-utils)/ }
];

// Fast keyword filter: if text does not contain ANY of these substrings, skip scanning in 0.01ms!
const FAST_SCAN_KEYWORDS = [
  'import', 'require', 'define(', '__webpack_require__', 'node_modules',
  'dependencies', 'devdependencies', 'unpkg', 'jsdelivr', 'cdnjs', 'esm.sh', 'skypack',
  'react', 'vue', 'angular', 'jquery', 'lodash', 'axios', 'sentry', 'core-js', 'moment', 'next', 'nuxt',
  'requirements.txt', 'package.json', 'composer.json', 'go.mod', 'cargo.toml',
  'pom.xml', 'build.gradle', 'packages.config', '.npmrc', '.env'
];

class KatanaSupplyChainScanner {
  constructor() {
    this.evaluatedCache = new SupplyChainLRUCache(512); // key -> evaluated record
    this.pendingQueries = new Map(); // key -> Promise
    this.nodeBuiltins = NODE_BUILTINS;

    // Background evaluation queue
    this.evalQueue = [];
    this.isProcessingQueue = false;
    this.maxConcurrentEval = 6;
    this.activeEvalCount = 0;

    // Precompile regex patterns once
    this.compilePatterns();
  }

  compilePatterns() {
    // 1. CommonJS require: require('pkg') or require("pkg/subpath")
    this.rxRequire = /(?<!@)\brequire\s*(?:\.resolve)?\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

    // 2. ES6 static import: import ... from 'pkg'
    this.rxImportFrom = /(?<!@)\bimport\s+(?!type\b)(?:[\w*\s{},$]+\s+from\s+)?['"]([^'"]+)['"]/g;

    // 3. Dynamic import: import('pkg')
    this.rxDynamicImport = /(?<!@)\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

    // 4. ES6 export from: export ... from 'pkg'
    this.rxExportFrom = /(?<!@)\bexport\s+(?!type\b)(?:[\w*\s{},$]+\s+from\s+)['"]([^'"]+)['"]/g;

    // 5. AMD / RequireJS: define(['pkg', 'pkg2'], ...)
    this.rxAmdDefine = /(?<!@)\bdefine\s*\(\s*(?:['"][^'"]*['"]\s*,\s*)?\[\s*([^\]]+)\]/g;

    // 6. Webpack runtime: __webpack_require__('pkg') or require.ensure(['pkg'], ...)
    this.rxWebpack = /(?<!@)(?:__webpack_require__\s*\(|require\.ensure\s*\(\s*\[)\s*['"]([^'"]+)['"]/g;

    // 7. SystemJS: System.import('pkg')
    this.rxSystemJs = /(?<!@)\bSystem\.import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

    // 8. Public CDNs (unpkg, jsdelivr, esm.sh, skypack)
    this.rxCdn = /(?:cdn\.jsdelivr\.net\/npm\/|unpkg\.com\/|esm\.sh\/|cdn\.skypack\.dev\/)(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)(?:@([0-9a-zA-Z._\-]+))?/g;

    // 9. cdnjs.cloudflare.com: cdnjs.cloudflare.com/ajax/libs/<pkg>/[version]
    this.rxCdnjs = /cdnjs\.cloudflare\.com\/ajax\/libs\/([a-zA-Z0-9_.\-]+)(?:\/([0-9a-zA-Z._\-]+))?/g;

    // 10. Sourcemap & bundled node_modules paths
    this.rxSourceMapModules = /(?:webpack:\/\/\/|\/|^)(?:node_modules|\/~\/)\/(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)/g;

    // 11. Python / PyPI requirements.txt format
    this.rxPythonReq = /^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=|!=)\s*([0-9a-zA-Z._\-]+)/gm;

    // 12. PHP composer.json dependency line
    this.rxComposer = /"([a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-]+)"\s*:\s*"([^"]+)"/g;

    // 13. Rust Cargo.toml dependency line
    this.rxCargo = /^\s*([a-zA-Z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*|)['"]([0-9a-zA-Z._\-]+)/gm;

    // 14. Go go.mod dependency line
    this.rxGoMod = /^\s*(?:require\s+)?([a-zA-Z0-9_.\-\/]+)\s+v([0-9a-zA-Z._\-]+)/gm;

    // 15. Java Maven / Gradle dependencies
    this.rxMavenDep = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/gi;
    this.rxGradleDep = /(?:implementation|api|compile)\s*['"]([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)(?::([a-zA-Z0-9_.-]+))?['"]/g;

    // 16. .NET NuGet package references
    this.rxNuget = /(?:<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?|<package\s+id="([^"]+)"(?:\s+version="([^"]+)")?)/gi;

    // 17. Exposed config / manifest paths referenced in code
    this.rxConfigPaths = /['"](\/(?:package\.json|package-lock\.json|\.npmrc|\.yarnrc|\.env|\.env\.[a-z]+|requirements\.txt|Pipfile|composer\.json|go\.mod|Cargo\.toml|pom\.xml))['"]/gi;

    // 18. Banner comment library version detection (e.g., /*! React v18.2.0 */ or /*! jQuery v3.6.0 */)
    this.rxBannerVersion = /(?:\/\*!|\/\*\*?)\s*(?:[^\n*]*\b)?([A-Za-z0-9_.\-]+)\s+(?:v|version\s*:?)\s*([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z_-]+)?)/gi;

    // 19. Filename package detection (e.g., /vendor/jquery-3.6.0.min.js, /react@18.2.0/...)
    this.rxFilenamePkg = /(?:^|\/)([a-zA-Z0-9_\-]+)[@\-_]([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z._\-]+)?)(?:\.bundle|\.min)?\.(?:js|mjs|cjs)/i;
  }

  /**
   * Fast keyword check: skip non-code/plain text blobs in 0.01ms
   */
  hasRelevantKeywords(text, sourceUrl = '') {
    if (!text || typeof text !== 'string') return false;
    const lowerUrl = (sourceUrl || '').toLowerCase();
    const cleanUrl = lowerUrl.split('?')[0].split('#')[0];
    if (/\.(?:js|mjs|cjs|jsx|tsx|ts|map|json|txt|toml|xml|gradle)$/i.test(cleanUrl)) {
      return true;
    }
    if (/(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|pipfile|gemfile|composer\.json|go\.mod|cargo\.toml|pom\.xml|build\.gradle|packages\.config|\.env)/i.test(lowerUrl)) {
      return true;
    }
    if (lowerUrl.includes('unpkg.com') || lowerUrl.includes('jsdelivr.net') || lowerUrl.includes('cdnjs.cloudflare.com') || lowerUrl.includes('esm.sh') || lowerUrl.includes('skypack.dev')) {
      return true;
    }
    const sample = text.length > 200000 ? (text.slice(0, 100000) + text.slice(-100000)).toLowerCase() : text.toLowerCase();
    for (let i = 0; i < FAST_SCAN_KEYWORDS.length; i++) {
      if (sample.includes(FAST_SCAN_KEYWORDS[i])) return true;
    }
    return false;
  }

  /**
   * Strips comments and TypeScript type declarations before matching
   */
  stripNonCode(content) {
    if (!content || typeof content !== 'string') return '';
    return content
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '')
      .replace(/(?:^|[\s;])import\s+type\s+[^;]*?from\s+['"][^'"]+['"]\s*;?/g, '')
      .replace(/(?:^|[\s;])export\s+type\s+[^;]*?from\s+['"][^'"]+['"]\s*;?/g, '');
  }

  /**
   * Cleans and validates package specifiers
   */
  normalizePackageSpecifier(specifier, eco = 'npm') {
    if (!specifier || typeof specifier !== 'string') return null;

    let clean = specifier.trim().replace(/^["'`]|["'`]$/g, '').split('#')[0].split('?')[0];
    if (!clean || clean.length < 2 || clean.length > 120) return null;

    // Drop absolute URLs, data URIs, or file paths
    if (/^(https?:|data:|blob:|file:|\*)/i.test(clean)) return null;

    // Drop relative paths and framework aliases
    for (const prefix of LOCAL_PATH_PREFIXES) {
      if (clean.startsWith(prefix)) return null;
    }

    // Check if the root component is a local alias (e.g. 'src/components/Button')
    const parts = clean.split('/');
    if (eco === 'npm' && parts.length > 1 && !clean.startsWith('@')) {
      if (INTERNAL_ROOTS.has(parts[0].toLowerCase())) return null;
    }

    // Extract base package from subpath (e.g. 'lodash/merge' -> 'lodash', '@scope/pkg/sub' -> '@scope/pkg')
    let basePkg = clean;
    if (eco === 'npm') {
      if (clean.startsWith('@')) {
        if (parts.length >= 2) {
          basePkg = `${parts[0]}/${parts[1]}`;
        } else {
          return null;
        }
      } else if (clean.includes('/')) {
        basePkg = parts[0];
      }
    }

    // Check against internal module patterns
    for (const item of INTERNAL_MODULE_PATTERNS) {
      if (item.pattern.test(clean) || item.pattern.test(basePkg)) {
        return null;
      }
    }

    // Filter Node builtins
    const lower = basePkg.toLowerCase();
    if (eco === 'npm' && this.nodeBuiltins.has(lower)) {
      return null;
    }

    // Validate syntax
    if (eco === 'npm') {
      if (!/^(@[a-z0-9\-~][a-z0-9\-._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/i.test(basePkg)) {
        return null;
      }
      return lower;
    }

    return basePkg;
  }

  extractContext(content, matchIndex, matchLength) {
    const start = Math.max(0, matchIndex - 60);
    const end = Math.min(content.length, matchIndex + matchLength + 60);
    let snippet = content.slice(start, end).replace(/[\r\n]+/g, ' ').trim();
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';
    return snippet;
  }

  /**
   * Main scan method matching KatanaSecretScanner signature:
   * scan(content, sourceUrl, sourceType) -> Array of findings
   */
  scan(content, sourceUrl = '', sourceType = 'js-bundle') {
    if (!content || typeof content !== 'string' || content.length < 5) {
      return [];
    }

    // Fast keyword check
    if (!this.hasRelevantKeywords(content, sourceUrl)) {
      return [];
    }

    // Performance safety: limit scan buffer to 3MB
    const textToScan = content.length > 3000000 ? content.slice(0, 3000000) : content;
    const cleanCode = this.stripNonCode(textToScan);
    const discovered = new Map(); // key -> finding

    const registerPackage = (rawName, version = '', eco = 'npm', contextSnippet = '') => {
      const normalizedName = this.normalizePackageSpecifier(rawName, eco);
      if (!normalizedName) return;

      const cleanVersion = String(version || '').replace(/^[\^~>=<]+/, '').replace(/\.(min|bundle|umd|cjs|esm)$/i, '').trim();
      const key = `${eco}:${normalizedName}`;

      if (discovered.has(key)) {
        const existing = discovered.get(key);
        if (!existing.version && cleanVersion) {
          existing.version = cleanVersion;
        }
        return;
      }

      // Check if we already evaluated this package previously (instant LRU hit)
      const cached = this.evaluatedCache.get(key);

      discovered.set(key, {
        key,
        type: 'package',
        name: normalizedName,
        version: cleanVersion,
        ecosystem: eco,
        riskLevel: cached ? cached.riskLevel : 'LOW',
        riskReasons: cached ? (cached.riskReasons || []) : [],
        isUnregistered: cached ? Boolean(cached.isUnregistered) : false,
        advisories: cached ? (cached.advisories || []) : [],
        advisoriesCount: cached ? (cached.advisoriesCount || (cached.advisories ? cached.advisories.length : 0)) : 0,
        weeklyDownloads: cached && cached.weeklyDownloads != null ? cached.weeklyDownloads : 0,
        sourceUrl,
        sourceType,
        context: (contextSnippet || '').slice(0, 300),
        discoveredAt: Date.now()
      });
    };

    // 1. Direct JSON Manifest check (package.json, importmap)
    if (textToScan.startsWith('{') || textToScan.includes('"dependencies"') || textToScan.includes('"imports"')) {
      try {
        const parsed = JSON.parse(textToScan);

        // A. Node package.json dependencies
        if (parsed.dependencies || parsed.devDependencies || parsed.peerDependencies || parsed.optionalDependencies) {
          const allDeps = {
            ...(parsed.dependencies || {}),
            ...(parsed.devDependencies || {}),
            ...(parsed.peerDependencies || {}),
            ...(parsed.optionalDependencies || {})
          };
          for (const [depName, depVer] of Object.entries(allDeps)) {
            registerPackage(depName, String(depVer), 'npm', `Manifest dependency: ${depName}@${depVer}`);
          }
        }

        // B. HTML5 Import Maps (<script type="importmap">)
        if (parsed.imports && typeof parsed.imports === 'object') {
          for (const [specifier, target] of Object.entries(parsed.imports)) {
            registerPackage(specifier, '', 'npm', `Import map: ${specifier} -> ${target}`);
          }
        }
      } catch (e) {
        // Fall back to regex parsing if not strictly JSON
      }
    }

    // 2. CommonJS require('...')
    this.rxRequire.lastIndex = 0;
    let m;
    while ((m = this.rxRequire.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 3. ES6 import ... from '...'
    this.rxImportFrom.lastIndex = 0;
    while ((m = this.rxImportFrom.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 4. Dynamic import('...')
    this.rxDynamicImport.lastIndex = 0;
    while ((m = this.rxDynamicImport.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 5. ES6 export ... from '...'
    this.rxExportFrom.lastIndex = 0;
    while ((m = this.rxExportFrom.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 6. AMD define(['...', '...'])
    this.rxAmdDefine.lastIndex = 0;
    while ((m = this.rxAmdDefine.exec(cleanCode)) !== null) {
      const items = m[1].split(',');
      const ctx = this.extractContext(cleanCode, m.index, m[0].length);
      for (const item of items) {
        const raw = item.trim().replace(/^["']|["']$/g, '');
        if (raw && !this.nodeBuiltins.has(raw.toLowerCase())) {
          registerPackage(raw, '', 'npm', ctx);
        }
      }
    }

    // 7. Webpack runtime imports
    this.rxWebpack.lastIndex = 0;
    while ((m = this.rxWebpack.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 8. System.import('...')
    this.rxSystemJs.lastIndex = 0;
    while ((m = this.rxSystemJs.exec(cleanCode)) !== null) {
      registerPackage(m[1], '', 'npm', this.extractContext(cleanCode, m.index, m[0].length));
    }

    // 9. Public CDNs (unpkg, jsdelivr, esm.sh, skypack)
    this.rxCdn.lastIndex = 0;
    while ((m = this.rxCdn.exec(textToScan)) !== null) {
      registerPackage(m[1], m[2] || '', 'npm', this.extractContext(textToScan, m.index, m[0].length));
    }

    // 10. cdnjs.cloudflare.com
    this.rxCdnjs.lastIndex = 0;
    while ((m = this.rxCdnjs.exec(textToScan)) !== null) {
      registerPackage(m[1], m[2] || '', 'npm', this.extractContext(textToScan, m.index, m[0].length));
    }

    // 11. Sourcemap & bundled node_modules paths
    if (sourceType === 'source-map' || sourceType === 'js-bundle' || sourceUrl.endsWith('.map') || textToScan.includes('node_modules')) {
      this.rxSourceMapModules.lastIndex = 0;
      while ((m = this.rxSourceMapModules.exec(textToScan)) !== null) {
        registerPackage(m[1], '', 'npm', `Bundled module: ${m[0]}`);
      }
    }

    // 11b. Banner comment library version detection (e.g. /*! React v18.2.0 */)
    if (this.rxBannerVersion) {
      this.rxBannerVersion.lastIndex = 0;
      while ((m = this.rxBannerVersion.exec(textToScan)) !== null) {
        const candidateName = m[1].toLowerCase();
        const candidateVer = m[2];
        if (candidateName && candidateVer && candidateName.length >= 2 && candidateName.length <= 40) {
          registerPackage(candidateName, candidateVer, 'npm', this.extractContext(textToScan, m.index, m[0].length));
        }
      }
    }

    // 12. Python requirements.txt
    if (sourceUrl.includes('requirements.txt') || textToScan.includes('requirements.txt') || this.rxPythonReq.test(textToScan)) {
      this.rxPythonReq.lastIndex = 0;
      while ((m = this.rxPythonReq.exec(textToScan)) !== null) {
        registerPackage(m[1], m[2] || '', 'pypi', m[0]);
      }
    }

    // 13. PHP composer.json
    if (sourceUrl.includes('composer.json') || textToScan.includes('composer.json')) {
      this.rxComposer.lastIndex = 0;
      while ((m = this.rxComposer.exec(textToScan)) !== null) {
        registerPackage(m[1], m[2] || '', 'composer', m[0]);
      }
    }

    // 14. Rust Cargo.toml
    if (sourceUrl.includes('Cargo.toml') || textToScan.includes('Cargo.toml')) {
      this.rxCargo.lastIndex = 0;
      while ((m = this.rxCargo.exec(textToScan)) !== null) {
        registerPackage(m[1], m[2] || '', 'crates', m[0]);
      }
    }

    // 15. Go go.mod
    if (sourceUrl.includes('go.mod') || textToScan.includes('go.mod')) {
      this.rxGoMod.lastIndex = 0;
      while ((m = this.rxGoMod.exec(textToScan)) !== null) {
        registerPackage(m[1], m[2] || '', 'golang', m[0]);
      }
    }

    // 16. Java Maven & Gradle
    if (sourceUrl.includes('pom.xml') || textToScan.includes('<project')) {
      this.rxMavenDep.lastIndex = 0;
      while ((m = this.rxMavenDep.exec(textToScan)) !== null) {
        const fullName = `${m[1].trim()}:${m[2].trim()}`;
        registerPackage(fullName, m[3] ? m[3].trim() : '', 'maven', m[0]);
      }
    }
    if (sourceUrl.includes('build.gradle') || textToScan.includes('dependencies {')) {
      this.rxGradleDep.lastIndex = 0;
      while ((m = this.rxGradleDep.exec(textToScan)) !== null) {
        const fullName = `${m[1].trim()}:${m[2].trim()}`;
        registerPackage(fullName, m[3] ? m[3].trim() : '', 'maven', m[0]);
      }
    }

    // 17. .NET NuGet
    if (sourceUrl.includes('packages.config') || textToScan.includes('<PackageReference') || textToScan.includes('<package id=')) {
      this.rxNuget.lastIndex = 0;
      while ((m = this.rxNuget.exec(textToScan)) !== null) {
        const pkgName = m[1] || m[3];
        const pkgVer = m[2] || m[4] || '';
        if (pkgName) registerPackage(pkgName, pkgVer, 'nuget', m[0]);
      }
    }

    // 18. Exposed configuration / manifest file references
    if (sourceType === 'html' || sourceType === 'rendered-js' || sourceType === 'js-bundle') {
      this.rxConfigPaths.lastIndex = 0;
      while ((m = this.rxConfigPaths.exec(cleanCode)) !== null) {
        const foundPath = m[1];
        const key = `exposed:${foundPath}`;
        if (!discovered.has(key)) {
          discovered.set(key, {
            key,
            type: 'exposed-file',
            path: foundPath,
            name: foundPath,
            status: 200,
            contentType: 'config',
            riskLevel: 'HIGH',
            riskReasons: [`Exposed manifest/config reference: ${foundPath}`],
            isUnregistered: false,
            advisories: [],
            advisoriesCount: 0,
            weeklyDownloads: 0,
            sourceUrl,
            sourceType,
            context: this.extractContext(cleanCode, m.index, m[0].length),
            discoveredAt: Date.now()
          });
        }
      }
    }

    return Array.from(discovered.values());
  }

  /**
   * Non-blocking background evaluation queue.
   * Feeds discovered packages into background registry & OSV CVE checks.
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
          version: item.version || cached.version || '',
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
          console.warn('[SupplyChainScanner] Evaluation worker error:', err);
        } finally {
          this.activeEvalCount--;
          this.processQueue();
        }
      })();
    }

    this.isProcessingQueue = false;
  }

  /**
   * Evaluates a package with background service worker (OSV CVE lookup + registry check)
   */
  async evaluatePackage(item) {
    if (!item || item.type !== 'package') return item;
    const cacheKey = `${item.ecosystem || 'npm'}:${item.name}`;

    if (this.evaluatedCache.has(cacheKey)) {
      const cached = this.evaluatedCache.get(cacheKey);
      return {
        ...item,
        version: item.version || cached.version || '',
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
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          const response = await chrome.runtime.sendMessage({
            action: 'analyzePackage',
            name: item.name,
            ecosystem: item.ecosystem || 'npm',
            version: item.version,
            sources: [{ url: item.sourceUrl, context: item.context }],
            options: { osvLookup: true }
          });

          if (response) {
            const evaluatedData = {
              ...response,
              evaluatedAt: Date.now()
            };
            this.evaluatedCache.set(cacheKey, evaluatedData);

            return {
              ...item,
              version: item.version || response.version || '',
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
        }
      } catch (err) {
        console.warn(`[SupplyChainScanner] Evaluation failed for ${item.name}:`, err);
      } finally {
        this.pendingQueries.delete(cacheKey);
      }
      return item;
    })();

    this.pendingQueries.set(cacheKey, queryPromise);
    return queryPromise;
  }

  scanCode(code, sourceUrl, sourceType = 'js') {
    return this.scan(code, sourceUrl, sourceType);
  }

  scanJson(jsonContent, sourceUrl) {
    return this.scan(jsonContent, sourceUrl, 'json');
  }

  scanUrl(url) {
    if (!url || typeof url !== 'string') return [];
    const discovered = [];
    const findings = this.scan(url, url, 'script-url');
    if (Array.isArray(findings) && findings.length > 0) {
      discovered.push(...findings);
    }
    if (this.rxFilenamePkg) {
      this.rxFilenamePkg.lastIndex = 0;
      const cleanPath = url.split('?')[0].split('#')[0];
      const match = this.rxFilenamePkg.exec(cleanPath);
      if (match) {
        const pkgName = match[1];
        const pkgVer = (match[2] || '').replace(/\.(min|bundle|umd|cjs|esm)$/i, '');
        const normalized = this.normalizePackageSpecifier(pkgName, 'npm');
        if (normalized && !discovered.some(d => d.name === normalized)) {
          discovered.push({
            key: `npm:${normalized}`,
            type: 'package',
            name: normalized,
            version: pkgVer || '',
            ecosystem: 'npm',
            riskLevel: 'LOW',
            riskReasons: [],
            isUnregistered: false,
            advisories: [],
            advisoriesCount: 0,
            weeklyDownloads: 0,
            sourceUrl: url,
            sourceType: 'script-url',
            context: url,
            discoveredAt: Date.now()
          });
        }
      }
    }
    return discovered;
  }
}

const _rootSupply = (typeof globalThis !== 'undefined') ? globalThis : (typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : this));
_rootSupply.KatanaSupplyChainScanner = KatanaSupplyChainScanner;
if (typeof window !== 'undefined') {
  window.katanaSupplyChainScanner = new KatanaSupplyChainScanner();
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KatanaSupplyChainScanner };
}
