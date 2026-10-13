/**
 * Katana Web Crawler - Core Engine
 * Implements ProjectDiscovery Katana-style endpoint parsing, single-tab interactive crawling
 * (with CAPTCHA detection and solving), deep JS bundle analysis, and LinkFinder regex extraction.
 */

/**
 * Standalone in-tab content inspection function for chrome.scripting.executeScript
 * Standard function declaration ensures valid string serialization across V8 runtimes.
 */
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

  // 2. Extract DOM links
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

  // 3. Extract Script sources
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

  // 4. Extract Form actions
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

  // 5. Extract Inline Scripts & JSON routing blobs
  try {
    document.querySelectorAll('script:not([src])').forEach(script => {
      try {
        const content = script.textContent || '';
        if (content.length > 5 && content.length < 500000) {
          const type = (script.getAttribute('type') || '').toLowerCase();
          const id = (script.id || '').toLowerCase();
          if (type.includes('json') || id.includes('next') || id.includes('nuxt')) {
            result.jsonBlobs.push(content);
          } else {
            result.inlineScripts.push(content);
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // 6. Extract Meta tag URLs
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

  // 7. Extract HTML Comments
  try {
    const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT);
    let curNode;
    let count = 0;
    while ((curNode = iterator.nextNode()) && count < 150) {
      if (curNode.nodeValue && curNode.nodeValue.length < 5000) {
        result.htmlComments.push(curNode.nodeValue);
        count++;
      }
    }
  } catch(e) {}

  // 8. Extract data-* attributes
  try {
    const pathAttrRegex = /^(?:data-(?:url|href|src|path|endpoint|route|api|target)|action|formaction|cite|ping|poster|manifest)$/i;
    document.querySelectorAll('*').forEach(el => {
      try {
        if (el.attributes) {
          for (const attr of el.attributes) {
            if (pathAttrRegex.test(attr.name) && attr.value && attr.value.length < 1000) {
              try {
                const resolved = new URL(attr.value, base).href;
                result.dataEndpoints.push({ name: attr.name, value: resolved });
              } catch(e) {
                result.dataEndpoints.push({ name: attr.name, value: attr.value });
              }
            }
          }
        }
      } catch(e) {}
    });
  } catch(e) {}

  // 9. Extract network resources from Performance API
  try {
    const resources = performance.getEntriesByType('resource');
    resources.forEach(r => {
      try {
        if (r.name && !r.name.startsWith('data:') && !r.name.startsWith('blob:')) {
          result.networkResources.push({
            name: r.name,
            initiatorType: r.initiatorType || 'resource'
          });
        }
      } catch(e) {}
    });
  } catch(e) {}

  // 10. Extract CSS stylesheets
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
    document.querySelectorAll('style').forEach(el => {
      try {
        const content = el.textContent || '';
        if (content.length > 5 && content.length < 200000) result.inlineStyles.push(content);
      } catch(e) {}
    });
  } catch(e) {}

  // 11. Capture HTML slice safely
  try {
    result.rawHtml = document.documentElement ? document.documentElement.outerHTML.slice(0, 300000) : '';
  } catch(e) {
    result.rawHtml = '';
  }

  return result;
}

/**
 * Standalone in-tab click exploration function for chrome.scripting.executeScript
 */
function katanaInTabClickExplorationScript(maxClicks = 8) {
  return new Promise((resolve) => {
    const clickedResults = {
      clickedCount: 0,
      interceptedRequests: [],
      newDomLinks: [],
      navigatedRoutes: []
    };

    const origAlert = window.alert;
    const origConfirm = window.confirm;
    const origPrompt = window.prompt;
    try {
      window.alert = () => {};
      window.confirm = () => false;
      window.prompt = () => null;
    } catch(e) {}

    const originalFetch = window.fetch;
    const originalXhrOpen = XMLHttpRequest.prototype.open;
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    try {
      window.fetch = function(...args) {
        try {
          const u = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url ? args[0].url : '');
          if (u) clickedResults.interceptedRequests.push(u);
        } catch(e) {}
        return originalFetch.apply(this, args);
      };

      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        try {
          if (url) clickedResults.interceptedRequests.push(url);
        } catch(e) {}
        return originalXhrOpen.apply(this, [method, url, ...rest]);
      };

      history.pushState = function(state, unused, url) {
        if (url) clickedResults.navigatedRoutes.push(url);
        return originalPushState.apply(this, arguments);
      };

      history.replaceState = function(state, unused, url) {
        if (url) clickedResults.navigatedRoutes.push(url);
        return originalReplaceState.apply(this, arguments);
      };
    } catch(e) {}

    let isFinished = false;
    let safetyTimer = null;

    function cleanup() {
      if (isFinished) return;
      isFinished = true;
      try {
        if (safetyTimer) clearTimeout(safetyTimer);
        window.alert = origAlert;
        window.confirm = origConfirm;
        window.prompt = origPrompt;
        window.fetch = originalFetch;
        XMLHttpRequest.prototype.open = originalXhrOpen;
        history.pushState = originalPushState;
        history.replaceState = originalReplaceState;

        const base = document.baseURI || window.location.href;
        document.querySelectorAll('a[href], link[href], form[action]').forEach(el => {
          const val = el.href || el.getAttribute('href') || el.getAttribute('action');
          if (val) {
            try {
              clickedResults.newDomLinks.push(new URL(val, base).href);
            } catch(e) {
              clickedResults.newDomLinks.push(val);
            }
          }
        });

        performance.getEntriesByType('resource').forEach(r => {
          if (r.name && !r.name.startsWith('data:') && !r.name.startsWith('blob:')) {
            clickedResults.interceptedRequests.push(r.name);
          }
        });
      } catch(e) {}
    }

    safetyTimer = setTimeout(() => {
      cleanup();
      resolve(clickedResults);
    }, 1200);

    const destructiveRegex = /log\s*out|sign\s*out|delete|remove|destroy|trash|cancel\s*account|submit|checkout|buy|pay|leave|exit/i;
    const selectors = [
      'button:not([type="submit"])',
      'input[type="button"]',
      '[role="button"]',
      '[role="tab"]',
      '[role="menuitem"]',
      'a[href="#"]',
      'a[href^="javascript:"]',
      '.btn:not([type="submit"])',
      '.button:not([type="submit"])',
      '.tab',
      '.nav-link'
    ];

    let elements = [];
    try {
      elements = document.querySelectorAll(selectors.join(', '));
    } catch(e) {}

    const candidates = [];
    for (const el of elements) {
      try {
        if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
        if (el.closest('form') && (el.type === 'submit' || (el.tagName === 'BUTTON' && !el.type))) continue;

        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;

        const text = (el.innerText || el.value || el.title || el.getAttribute('aria-label') || '').trim();
        if (destructiveRegex.test(text)) continue;

        candidates.push(el);
        if (candidates.length >= maxClicks) break;
      } catch(e) {}
    }

    if (candidates.length === 0) {
      cleanup();
      resolve(clickedResults);
      return;
    }

    let idx = 0;
    function clickNext() {
      if (isFinished) return;
      if (idx >= candidates.length) {
        cleanup();
        resolve(clickedResults);
        return;
      }

      const el = candidates[idx++];
      try {
        clickedResults.clickedCount++;
        const preventNav = (e) => {
          if (el.tagName === 'A' || el.closest('form') || el.type === 'submit') {
            e.preventDefault();
          }
        };
        el.addEventListener('click', preventNav, { capture: true, once: true });
        el.click();
        el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
      } catch(e) {}

      setTimeout(clickNext, 40);
    }

    clickNext();
  });
}

class KatanaCrawlerEngine {
  constructor(storage) {
    this.storage = storage;
    this.isRunning = false;
    this.isPaused = false;
    this.isWaitingForCaptcha = false;
    this.abortController = null;
    this.crawlerTabId = null;

    // Configuration defaults
    this.config = {
      mode: 'single-tab', // 'single-tab' (interactive browser tab) or 'fast-fetch' (background HTTP)
      concurrency: 1,     // In single-tab mode, concurrency is strictly 1 (single tab); in fast-fetch, up to 30
      maxDepth: 3,        // Follow discovered in-scope endpoints in the browser tab (default depth 3)
      timeout: 8000,      // 8s timeout per request/tab load
      tabRenderDelay: 400, // 400ms delay after DOM load for JS hydration
      scopeMode: 'same-domain', // 'same-domain', 'same-root', 'regex', 'all'
      scopeRegex: '',
      subdomainCrawl: true,     // Crawl discovered subdomains (*.example.com) when enabled
      openFoundUrlsInTab: true, // Automatically open discovered URLs in the single tab (excluding static assets)
      crawlJavascript: true,    // Deep JS crawl: Fetch & regex-extract external JS bundles
      autoClickButtons: true,   // Automatically click buttons & interactive elements to discover dynamic endpoints
      maxButtonClicks: 8,       // Maximum 8 buttons per page for rapid exploration
      parseRobotsAndSitemaps: true, // Check robots.txt and sitemap.xml
      ignoreFileExtensions: ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip'],
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Katana/1.1',
      delayMs: 100 // Rapid 100ms delay between requests
    };

    // State
    this.queue = [];
    this.enqueuedUrls = new Set(); // Strict queue deduplication set
    this.visitedUrls = new Set();  // Visited URLs set
    this.sessionDiscoveredUrls = new Set(); // Session URL deduplication set
    this.subdomainsDiscovered = new Set(); // Unique discovered subdomains
    this.duplicatesFiltered = 0;   // Count of duplicate URLs filtered
    this.totalDiscoveredInSession = 0;
    this.crawledCount = 0;
    this.errorCount = 0;
    this.startTime = null;
    this.activeWorkers = 0;
    this.currentCaptchaTarget = null;
    this.captchaCheckInterval = null;

    // Secret Scanner Engine
    this.secretScanner = (typeof KatanaSecretScanner !== 'undefined') ? new KatanaSecretScanner() : null;
    this.totalSecretsInSession = 0;

    // Supply Chain & NPM Dependency Scanner Engine
    this.supplyChainScanner = (typeof KatanaSupplyChainScanner !== 'undefined') ? new KatanaSupplyChainScanner() : null;
    this.totalSupplyChainInSession = 0;

    // Callbacks
    this.onLog = null;
    this.onProgress = null;
    this.onStatsUpdate = null;
    this.onUrlFound = null;
    this.onSecretFound = null;
    this.onSupplyChainFinding = null;
    this.onStateChange = null;
    this.onCaptchaDetected = null;
    this.onCaptchaResolved = null;
  }

  log(level, message, details = '') {
    const timestamp = new Date().toLocaleTimeString();
    if (this.onLog) {
      this.onLog({ timestamp, level, message, details });
    }
    console.log(`[${level.toUpperCase()}] ${message}`, details);
  }

  configure(newConfig) {
    this.config = { ...this.config, ...newConfig };
    if (this.config.mode === 'single-tab') {
      this.config.concurrency = 1; // Strict 1 tab in single-tab mode
    }
  }

  // Apex domain helper (e.g. sub.example.com -> example.com)
  getApexDomain(hostname) {
    if (!hostname) return '';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':')) {
      return hostname;
    }
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join('.');
  }

  isInScope(candidateUrl, seedUrl) {
    if (this.config.scopeMode === 'all') return true;

    try {
      const candidateObj = new URL(candidateUrl);
      const seedObj = new URL(seedUrl);

      const candidateHost = candidateObj.hostname.replace(/^www\./i, '').toLowerCase();
      const seedHost = seedObj.hostname.replace(/^www\./i, '').toLowerCase();

      // Custom regex scope mode takes highest priority if selected
      if (this.config.scopeMode === 'regex' && this.config.scopeRegex) {
        try {
          const re = new RegExp(this.config.scopeRegex, 'i');
          return re.test(candidateUrl);
        } catch {
          return false;
        }
      }

      // Subdomain Crawl Mode: If enabled, any URL matching the seed's apex domain (*.domain.com) is in-scope
      if (this.config.subdomainCrawl) {
        const candidateApex = this.getApexDomain(candidateObj.hostname).toLowerCase();
        const seedApex = this.getApexDomain(seedObj.hostname).toLowerCase();
        if (candidateApex && seedApex && candidateApex === seedApex) {
          return true;
        }
      }

      if (this.config.scopeMode === 'same-domain') {
        return candidateHost === seedHost;
      }

      if (this.config.scopeMode === 'same-root') {
        return this.getApexDomain(candidateObj.hostname).toLowerCase() === this.getApexDomain(seedObj.hostname).toLowerCase();
      }

      return candidateHost === seedHost;
    } catch {
      return false;
    }
  }

  /**
   * Strict Canonical URL Normalizer for 100% Deterministic Deduplication
   */
  canonicalUrl(rawUrl, baseUrl = null) {
    if (!rawUrl || typeof rawUrl !== 'string') return null;

    let trimmed = rawUrl.trim();
    if (!trimmed) return null;

    if (/^(?:javascript|mailto|data|tel|sms|blob|about|android-app|ios-app):/i.test(trimmed)) {
      return null;
    }

    try {
      let resolved;
      if (baseUrl) {
        resolved = new URL(trimmed, baseUrl);
      } else {
        if (!/^https?:\/\//i.test(trimmed)) {
          trimmed = 'http://' + trimmed;
        }
        resolved = new URL(trimmed);
      }

      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
        return null;
      }

      // 1. Lowercase hostname
      resolved.hostname = resolved.hostname.toLowerCase();

      // 2. Remove default ports
      if ((resolved.protocol === 'http:' && resolved.port === '80') ||
          (resolved.protocol === 'https:' && resolved.port === '443')) {
        resolved.port = '';
      }

      // 3. Drop fragment/hash
      resolved.hash = '';

      // 4. Normalize path: remove double slashes and strip trailing slash for non-root paths
      let pathname = resolved.pathname.replace(/\/+/g, '/');
      if (pathname.length > 1 && pathname.endsWith('/')) {
        pathname = pathname.slice(0, -1);
      }
      resolved.pathname = pathname;

      // 5. Deterministic query parameter sorting (e.g. ?b=2&a=1 -> ?a=1&b=2)
      if (resolved.search) {
        const params = new URLSearchParams(resolved.search);
        params.sort();
        const sorted = params.toString();
        resolved.search = sorted ? '?' + sorted : '';
      }

      return resolved.toString();
    } catch {
      return null;
    }
  }

  normalizeUrl(rawUrl, baseUrl = null) {
    return this.canonicalUrl(rawUrl, baseUrl);
  }

  /**
   * Determines if a URL is an HTML page / app endpoint suitable for opening in the browser tab.
   * Static assets (.js, .css, images, media, archives, fonts) return false so the tab is never
   * navigated to raw code or static files!
   */
  isNavigableInTab(url) {
    if (!url) return false;
    try {
      const pathname = new URL(url).pathname.toLowerCase();
      const nonNavigableExtensions = [
        '.js', '.mjs', '.cjs',
        '.css',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.flac', '.avi', '.mov',
        '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar', '.exe', '.dmg', '.pkg', '.apk', '.bin',
        '.map', '.txt'
      ];
      return !nonNavigableExtensions.some(ext => pathname.endsWith(ext));
    } catch {
      return false;
    }
  }

  /**
   * Extract subdomains from HTML text, scripts, and comments matching *.apexDomain
   */
  extractSubdomainsFromText(text, seedUrl) {
    const discovered = [];
    if (!text || typeof text !== 'string' || !this.config.subdomainCrawl) return discovered;

    try {
      const seedObj = new URL(seedUrl);
      const apexDomain = this.getApexDomain(seedObj.hostname).toLowerCase();
      if (!apexDomain) return discovered;

      const escaped = apexDomain.replace(/\./g, '\\.');
      const subRegex = new RegExp(`(?:https?:\\/\\/)?(([a-zA-Z0-9_\\-]+\\.)+${escaped})(?::\\d+)?`, 'gi');
      let match;

      while ((match = subRegex.exec(text)) !== null) {
        const fqdn = match[1].toLowerCase();
        if (fqdn !== seedObj.hostname.toLowerCase()) {
          this.subdomainsDiscovered.add(fqdn);
          const fullUrl = `${seedObj.protocol}//${fqdn}`;
          const canonical = this.canonicalUrl(fullUrl);
          if (canonical) {
            discovered.push({
              url: canonical,
              type: 'subdomain',
              sourceUrl: seedUrl
            });
          }
        }
      }
    } catch {}

    return discovered;
  }

  shouldIgnoreExtension(url) {
    try {
      const pathname = new URL(url).pathname.toLowerCase();
      return this.config.ignoreFileExtensions.some(ext => pathname.endsWith(ext));
    } catch {
      return false;
    }
  }

  /**
   * Comprehensive Katana & LinkFinder Regex Engine for JavaScript and Strings
   */
  extractEndpointsFromJs(jsContent, pageUrl) {
    const discovered = [];
    if (!jsContent || typeof jsContent !== 'string') return discovered;

    // 1. Full URLs: https?://...
    const fullUrlRegex = /https?:\/\/[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:\/[^\s"'\`<>]*)*[^\s"'\`<>.,;]/g;
    let match;
    while ((match = fullUrlRegex.exec(jsContent)) !== null) {
      const normalized = this.normalizeUrl(match[0]);
      if (normalized) {
        discovered.push({
          url: normalized,
          type: 'js-full-url',
          sourceUrl: pageUrl
        });
      }
    }

    // 2. Protocol-relative URLs: //example.com/path
    const protoRelativeRegex = /(?:["'`])(\/\/[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:\/[^\s"'\`<>]*)*)(?:["'`])/g;
    while ((match = protoRelativeRegex.exec(jsContent)) !== null) {
      const normalized = this.normalizeUrl(match[1], pageUrl);
      if (normalized) {
        discovered.push({
          url: normalized,
          type: 'js-proto-relative',
          sourceUrl: pageUrl
        });
      }
    }

    // 3. API calls: fetch('...'), axios.get('...')
    const apiCallRegex = /(?:fetch|axios\.(?:get|post|put|delete|patch)|open\(['"]GET['"]|open\(['"]POST['"])\s*\(\s*["'`]([^"'`\s]+)["'`]/gi;
    while ((match = apiCallRegex.exec(jsContent)) !== null) {
      const normalized = this.normalizeUrl(match[1], pageUrl);
      if (normalized) {
        discovered.push({
          url: normalized,
          type: 'js-api-call',
          sourceUrl: pageUrl
        });
      }
    }

    // 4. Katana Comprehensive Endpoint Regex (LinkFinder style)
    const katanaRegex = /(?:["'`])(((?:\/|\.\.\/|\.\/)[a-zA-Z0-9_\-\.~%!$&'()*+,;=:@/]{1,}(?:\?[a-zA-Z0-9_\-\.~%!$&'()*+,;=:@/?]*)?)|([a-zA-Z0-9_\-\/]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|api|wsdl)(?:\?[^"'\\\/\s]*)?)|(\/api(?:\/v\d+)?\/[a-zA-Z0-9_\-\/.]+)|(\/graphql(?:\?[^"'\\\/\s]*)?)|(\/rest\/[a-zA-Z0-9_\-\/.]+))(?:["'`])/g;

    while ((match = katanaRegex.exec(jsContent)) !== null) {
      const rawPath = match[1];
      if (!rawPath) continue;

      if (rawPath === '/' || rawPath === './' || rawPath === '../') continue;
      if (rawPath.startsWith('//')) continue;
      if (/\.(css|png|jpg|jpeg|gif|svg|woff|woff2|ico)$/i.test(rawPath)) continue;

      const normalized = this.normalizeUrl(rawPath, pageUrl);
      if (normalized) {
        discovered.push({
          url: normalized,
          type: 'js-endpoint',
          sourceUrl: pageUrl
        });
      }
    }

    return discovered;
  }

  /**
   * HTML Parsing (Static DOMParser fallback for fast-fetch mode)
   */
  extractUrlsFromHtml(html, pageUrl) {
    const discovered = [];
    const parser = new DOMParser();
    let doc;
    try {
      doc = parser.parseFromString(html, 'text/html');
    } catch {
      return discovered;
    }

    const baseEl = doc.querySelector('base[href]');
    const effectiveBase = baseEl ? (this.normalizeUrl(baseEl.getAttribute('href'), pageUrl) || pageUrl) : pageUrl;

    // Links
    doc.querySelectorAll('a[href], link[href], area[href]').forEach(el => {
      const normalized = this.normalizeUrl(el.getAttribute('href'), effectiveBase);
      if (normalized) discovered.push({ url: normalized, type: 'html-link', sourceUrl: pageUrl });
    });

    // Scripts
    doc.querySelectorAll('script[src]').forEach(el => {
      const normalized = this.normalizeUrl(el.getAttribute('src'), effectiveBase);
      if (normalized) discovered.push({ url: normalized, type: 'script-src', sourceUrl: pageUrl });
    });

    // Forms
    doc.querySelectorAll('form[action]').forEach(el => {
      const action = el.getAttribute('action') || '';
      const method = (el.getAttribute('method') || 'GET').toUpperCase();
      const normalized = this.normalizeUrl(action, effectiveBase);
      if (normalized) discovered.push({ url: normalized, type: `form-action[${method}]`, sourceUrl: pageUrl });
    });

    // Inline Scripts
    doc.querySelectorAll('script:not([src])').forEach(script => {
      const content = script.textContent || '';
      if (content.length > 5) {
        discovered.push(...this.extractEndpointsFromJs(content, pageUrl));
      }
    });

    return discovered;
  }

  /**
   * Extract asset URLs and font/image paths from CSS stylesheets
   */
  extractUrlsFromCss(cssContent, pageUrl) {
    const discovered = [];
    if (!cssContent || typeof cssContent !== 'string') return discovered;
    const cssUrlRegex = /url\(\s*['"]?([^'"()\s]+)['"]?\s*\)/gi;
    let match;
    while ((match = cssUrlRegex.exec(cssContent)) !== null) {
      const raw = match[1].trim();
      if (!raw || raw.startsWith('data:')) continue;
      const normalized = this.normalizeUrl(raw, pageUrl);
      if (normalized) {
        discovered.push({ url: normalized, type: 'css-asset', sourceUrl: pageUrl });
      }
    }
    return discovered;
  }

  /**
   * Parse robots.txt and sitemap.xml
   */
  async fetchRobotsAndSitemaps(seedUrl) {
    const discovered = [];
    try {
      const origin = new URL(seedUrl).origin;
      const robotsUrl = `${origin}/robots.txt`;

      const resp = await this.fetchWithTimeout(robotsUrl, { timeout: 5000 });
      if (resp && resp.ok) {
        const text = await resp.text();
        const lines = text.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          const lower = trimmed.toLowerCase();

          if (lower.startsWith('disallow:') || lower.startsWith('allow:')) {
            const path = trimmed.split(':')[1]?.trim();
            if (path && path !== '/' && !path.includes('*')) {
              const normalized = this.normalizeUrl(path, origin);
              if (normalized) {
                discovered.push({ url: normalized, type: 'robots.txt', sourceUrl: robotsUrl });
              }
            }
          } else if (lower.startsWith('sitemap:')) {
            const sitemapUrl = trimmed.substring(8).trim();
            const normalized = this.normalizeUrl(sitemapUrl, origin);
            if (normalized) {
              discovered.push({ url: normalized, type: 'sitemap-ref', sourceUrl: robotsUrl });
              const smUrls = await this.fetchSitemap(normalized);
              discovered.push(...smUrls);
            }
          }
        }
      }
    } catch {}
    return discovered;
  }

  async fetchSitemap(sitemapUrl) {
    const discovered = [];
    try {
      const resp = await this.fetchWithTimeout(sitemapUrl, { timeout: 6000 });
      if (resp && resp.ok) {
        const text = await resp.text();
        const locRegex = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
        let match;
        while ((match = locRegex.exec(text)) !== null) {
          const normalized = this.normalizeUrl(match[1]);
          if (normalized) discovered.push({ url: normalized, type: 'sitemap-loc', sourceUrl: sitemapUrl });
        }
      }
    } catch {}
    return discovered;
  }

  async fetchWithTimeout(url, { timeout = this.config.timeout, headers = {} } = {}) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
          ...headers
        },
        signal: controller.signal,
        credentials: 'omit',
        redirect: 'follow',
        cache: 'no-cache'
      });
      clearTimeout(id);
      return response;
    } catch (err) {
      clearTimeout(id);
      throw err;
    }
  }

  // =========================================================================
  // SINGLE-TAB CRAWLER ENGINE (Solves CAPTCHAs, executes JS, inspects tab)
  // =========================================================================

  async ensureCrawlerTab() {
    if (this.crawlerTabId) {
      try {
        const tab = await chrome.tabs.get(this.crawlerTabId);
        if (tab) return tab;
      } catch {
        this.crawlerTabId = null;
      }
    }

    // Create a new dedicated crawler tab
    const newTab = await chrome.tabs.create({ url: 'about:blank', active: true });
    this.crawlerTabId = newTab.id;
    this.log('inf', `[Browser] Opened dedicated crawler tab [ID: ${this.crawlerTabId}]`);
    return newTab;
  }

  async focusCrawlerTab() {
    if (this.crawlerTabId) {
      try {
        await chrome.tabs.update(this.crawlerTabId, { active: true });
        const tab = await chrome.tabs.get(this.crawlerTabId);
        if (tab.windowId) {
          await chrome.windows.update(tab.windowId, { focused: true });
        }
      } catch {}
    }
  }

  async focusTab() {
    return this.focusCrawlerTab();
  }

  /**
   * Fast-navigate the single tab: Resolves as soon as DOM is interactive/loaded
   * or complete, preventing waiting for slow trackers/ads/media!
   */
  /**
   * Fast-navigate the single tab: Resolves as soon as DOM is interactive/loaded
   * or complete, preventing waiting for slow trackers/ads/media!
   */
  async navigateTabAndWait(tabId, url, timeoutMs = 8000) {
    return new Promise((resolve) => {
      let isResolved = false;
      let timer = null;
      let pollInterval = null;
      let onUpdatedListener = null;
      let onRemovedListener = null;

      const finish = () => {
        if (isResolved) return;
        isResolved = true;
        if (timer) clearTimeout(timer);
        if (pollInterval) clearInterval(pollInterval);
        if (onUpdatedListener) chrome.tabs.onUpdated.removeListener(onUpdatedListener);
        if (onRemovedListener) chrome.tabs.onRemoved.removeListener(onRemovedListener);
        resolve(null);
      };

      // Tab closed by user
      onRemovedListener = (removedTabId) => {
        if (removedTabId === tabId) finish();
      };
      chrome.tabs.onRemoved.addListener(onRemovedListener);

      // Hard timeout
      const maxWait = Math.max(timeoutMs || 8000, 3000);
      timer = setTimeout(finish, maxWait);

      let navStarted = false;

      onUpdatedListener = (updatedTabId, changeInfo, tab) => {
        if (updatedTabId !== tabId) return;

        if (changeInfo.status === 'loading') {
          navStarted = true;
        }

        if (changeInfo.status === 'complete' && navStarted) {
          const tabUrl = tab?.url || '';
          if (tabUrl === 'about:blank' || tabUrl.startsWith('chrome://')) return;
          finish();
        }
      };
      chrome.tabs.onUpdated.addListener(onUpdatedListener);

      // Initiate navigation
      chrome.tabs.update(tabId, { url }).then(() => {
        let pollTicks = 0;
        pollInterval = setInterval(async () => {
          pollTicks++;
          try {
            const tab = await chrome.tabs.get(tabId);
            if (!tab) { finish(); return; }

            const tabUrl = tab.url || '';
            if (tabUrl === 'about:blank' || tabUrl.startsWith('chrome://')) return;

            if (tab.status === 'complete' && (navStarted || pollTicks >= 4)) {
              finish();
              return;
            }

            // Fallback: check readyState directly
            if (pollTicks >= 5) {
              try {
                const res = await chrome.scripting.executeScript({
                  target: { tabId },
                  func: () => document.readyState
                });
                const state = res?.[0]?.result;
                if (state === 'interactive' || state === 'complete') {
                  finish();
                  return;
                }
              } catch {}
            }
          } catch {
            if (navStarted) finish();
          }
        }, 200);
      }).catch(() => {
        finish();
      });
    });
  }

  static inTabExtractionScript() {
    return katanaInTabExtractionScript();
  }

  static inTabClickExplorationScript(maxClicks = 10) {
    return katanaInTabClickExplorationScript(maxClicks);
  }

  /**
   * Crawl a single target URL using the dedicated browser tab
   */
  async crawlItemSingleTab(item) {
    // NOTE: Do NOT put a short outer timeout here — all inner operations (nav, button clicks,
    // JS fetching, CSS fetching, source maps) already have their own individual timeouts.
    // A short outer race would kill _executeCrawlItemSingleTab BEFORE it reaches the enqueuing
    // step (~line 1477), leaving the queue empty and stopping the crawl completely.
    try {
      await this._executeCrawlItemSingleTab(item);
    } catch (err) {
      this.log('wrn', `Notice on ${item.url}: ${err.message}`);
    }
  }

  async _executeCrawlItemSingleTab(item) {
    let { url, seedUrl, depth, targetId } = item;
    this.log('inf', `[Browser Tab] Navigating [Depth ${depth}]: ${url}`);

    if (targetId) {
      await this.storage.updateTarget(targetId, { status: 'crawling' });
    }

    const tab = await this.ensureCrawlerTab();

    // 1. Navigate to target URL
    try {
      await this.navigateTabAndWait(tab.id, url, this.config.timeout);
    } catch (err) {
      this.log('wrn', `Navigation notice for ${url}: ${err.message}`);
    }

    // 2. Wait for client-side JavaScript / Single-Page Apps (React, Next.js, Vue) to render
    if (this.config.tabRenderDelay > 0) {
      await new Promise(r => setTimeout(r, this.config.tabRenderDelay));
    }

    // 3. Execute extraction inside the tab
    let tabData = null;
    try {
      const injectionResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: katanaInTabExtractionScript
      });
      tabData = injectionResults?.[0]?.result;
    } catch (err) {
      this.log('wrn', `Could not inspect tab content for ${url}: ${err.message}`);
    }

    if (!tabData || (tabData.pageUrl === 'about:blank' && url !== 'about:blank')) {
      this.log('inf', `[Browser Tab] Tab content pending, retrying inspection for ${url}...`);
      try {
        await new Promise(r => setTimeout(r, 600));
        const retryResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: katanaInTabExtractionScript
        });
        const retryData = retryResults?.[0]?.result;
        if (retryData && retryData.pageUrl !== 'about:blank') {
          tabData = retryData;
          this.log('inf', `[Browser Tab] Retry inspection succeeded for ${url}`);
        } else {
          this.log('wrn', `[Browser Tab] Retry inspection still pending for ${url}, attempting HTTP fallback`);
        }
      } catch (err) {
        this.log('wrn', `[Browser Tab] Retry inspection failed for ${url}: ${err.message}`);
      }
    }

    // 4. Check for CAPTCHA / Bot Verification
    if (tabData && tabData.captchaDetected) {
      this.log('wrn', `[CAPTCHA DETECTED] ${tabData.challengeType} on ${url}! Pausing crawler.`);
      await this.focusCrawlerTab();

      // Trigger callback so dashboard displays CAPTCHA solving banner
      this.isWaitingForCaptcha = true;
      this.currentCaptchaTarget = { url, tabId: tab.id, challengeType: tabData.challengeType };
      if (this.onCaptchaDetected) {
        this.onCaptchaDetected(this.currentCaptchaTarget);
      }

      // Wait until user solves it (or clicks resume)
      await this.waitForCaptchaResolution(tab.id);

      this.isWaitingForCaptcha = false;
      this.currentCaptchaTarget = null;
      if (this.onCaptchaResolved) this.onCaptchaResolved();
      this.log('inf', `[CAPTCHA RESOLVED] Continuing crawl on ${url}`);

      // Re-extract now that CAPTCHA has been solved!
      try {
        const reExtract = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: katanaInTabExtractionScript
        });
        tabData = reExtract?.[0]?.result;
      } catch {}
    }

    let discoveredInItem = [];
    const effectivePageUrl = tabData?.pageUrl || url;
    const discoveredSecrets = [];
    const discoveredSupplyChain = [];
    const sourceMapUrlsToFetch = [];

    // Automatically align seedUrl on depth 0 if the target seed redirected
    let effectiveSeedUrl = seedUrl;
    if (depth === 0 && effectivePageUrl) {
      try {
        const effObj = new URL(effectivePageUrl);
        const seedObj = new URL(seedUrl);
        const effApex = this.getApexDomain(effObj.hostname).toLowerCase();
        const seedApex = this.getApexDomain(seedObj.hostname).toLowerCase();
        if (effApex && seedApex && effApex === seedApex) {
          effectiveSeedUrl = effectivePageUrl;
        }
      } catch {}
    }

    // Probe origin manifests (.env, package.json, .npmrc, requirements.txt, etc.)
    // Asynchronously non-blocking so crawler tab progresses at maximum speed!
    if (this.supplyChainScanner && depth <= 1) {
      this.supplyChainScanner.probeOriginManifests(effectivePageUrl, (u, opts) => this.fetchWithTimeout(u, opts))
        .then(async (probed) => {
          if (!probed || probed.length === 0) return;
          const probeDiscovered = [];
          const probeSecrets = [];
          for (const p of probed) {
            if (p.url) probeDiscovered.push({ url: p.url, type: 'config', sourceUrl: effectivePageUrl, scope: 'in-scope', targetUrl: effectiveSeedUrl, depth });
            if (p.rawContent && this.secretScanner) {
              probeSecrets.push(...this.secretScanner.scan(p.rawContent, p.url, 'config'));
            }
          }
          if (probeDiscovered.length > 0) {
            await this.storage.addDiscoveredUrls(probeDiscovered);
            if (this.onUrlFound) this.onUrlFound(probeDiscovered);
          }
          if (probeSecrets.length > 0 && this.secretScanner) {
            await this.storage.saveSecrets(probeSecrets);
            if (this.onSecretFound) this.onSecretFound(probeSecrets);
          }
          await this.storage.saveSupplyChainFindings(probed);
          if (this.onSupplyChainFinding) this.onSupplyChainFinding(probed);
        }).catch(() => {});
    }

    // Fallback: If in-tab DOM inspection returned null (e.g. extension permission denied on error page or CSP sandbox), fetch directly
    if (!tabData) {
      try {
        this.log('inf', `[Engine Fallback] In-tab execution unavailable for ${url}, spidering via background HTTP engine...`);
        const resp = await this.fetchWithTimeout(url, { timeout: 8000 });
        if (resp && resp.ok) {
          const bodyText = await resp.text();
          const fallbackUrls = this.extractUrlsFromHtml(bodyText, url);
          discoveredInItem.push(...fallbackUrls);
          if (this.secretScanner) {
            discoveredSecrets.push(...this.secretScanner.scan(bodyText, url, 'html'));
          }
          if (this.supplyChainScanner) {
            discoveredSupplyChain.push(...this.supplyChainScanner.scan(bodyText, url, 'html'));
          }
          this.log('inf', `[Engine Fallback] Extracted ${fallbackUrls.length} links via background spider for ${url}`);

          // ── EARLY ENQUEUE: Fallback path ─────────────────────────────────
          for (const d of discoveredInItem) {
            if (!d.url || this.shouldIgnoreExtension(d.url)) continue;
            const canonical = this.canonicalUrl(d.url);
            if (!canonical) continue;
            if (this.isInScope(canonical, effectiveSeedUrl) &&
                depth < this.config.maxDepth &&
                this.isNavigableInTab(canonical) &&
                !this.visitedUrls.has(canonical) &&
                !this.enqueuedUrls.has(canonical)) {
              this.enqueuedUrls.add(canonical);
              this.queue.push({
                url: canonical,
                seedUrl: effectiveSeedUrl,
                depth: depth + 1,
                targetId: null
              });
              this.log('inf', `[Early Queue-FB] [Depth ${depth + 1}/${this.config.maxDepth}] ${canonical}`);
            }
          }
        }
      } catch (err) {
        this.log('wrn', `Fallback fetch failed for ${url}: ${err.message}`);
      }
    }

    if (tabData) {
      // 1. Scan Raw HTML Document Source with Secret Scanner & Katana Endpoint Regex
      if (tabData.rawHtml) {
        if (this.secretScanner) {
          discoveredSecrets.push(...this.secretScanner.scan(tabData.rawHtml, effectivePageUrl, 'html'));
        }
        if (this.supplyChainScanner) {
          discoveredSupplyChain.push(...this.supplyChainScanner.scan(tabData.rawHtml, effectivePageUrl, 'html'));
        }
        const rawEndpoints = this.extractEndpointsFromJs(tabData.rawHtml, effectivePageUrl);
        discoveredInItem.push(...rawEndpoints);
      }

      // 2. Scan Rendered DOM Inline Scripts & JSON Hydration Blobs
      for (const scriptText of tabData.inlineScripts || []) {
        if (this.secretScanner) {
          discoveredSecrets.push(...this.secretScanner.scan(scriptText, effectivePageUrl, 'rendered-js'));
        }
        if (this.supplyChainScanner) {
          discoveredSupplyChain.push(...this.supplyChainScanner.scan(scriptText, effectivePageUrl, 'rendered-js'));
        }
        const jsEndpoints = this.extractEndpointsFromJs(scriptText, effectivePageUrl);
        discoveredInItem.push(...jsEndpoints);

        // Check for Source Maps inside inline scripts
        if (typeof KatanaSecretScanner !== 'undefined') {
          const maps = KatanaSecretScanner.extractSourceMapUrls(scriptText, effectivePageUrl);
          sourceMapUrlsToFetch.push(...maps);
        }
      }

      // Next.js / Nuxt JSON Blobs & Hydration States
      for (const jsonStr of tabData.jsonBlobs || []) {
        if (this.secretScanner) {
          discoveredSecrets.push(...this.secretScanner.scan(jsonStr, effectivePageUrl, 'rendered-js'));
        }
        if (this.supplyChainScanner) {
          discoveredSupplyChain.push(...this.supplyChainScanner.scan(jsonStr, effectivePageUrl, 'rendered-js'));
        }
        const jsonEndpoints = this.extractEndpointsFromJs(jsonStr, effectivePageUrl);
        discoveredInItem.push(...jsonEndpoints);
      }

      // 3. Scan HTML Comments (staging secrets, dev routes, subdomains, dependency references)
      for (const comment of tabData.htmlComments || []) {
        if (this.secretScanner) {
          discoveredSecrets.push(...this.secretScanner.scan(comment, effectivePageUrl, 'html-comment'));
        }
        if (this.supplyChainScanner) {
          discoveredSupplyChain.push(...this.supplyChainScanner.scan(comment, effectivePageUrl, 'html-comment'));
        }
        const commentEndpoints = this.extractEndpointsFromJs(comment, effectivePageUrl);
        discoveredInItem.push(...commentEndpoints);
        if (this.config.subdomainCrawl) {
          const commentSubs = this.extractSubdomainsFromText(comment, seedUrl);
          discoveredInItem.push(...commentSubs);
        }
      }

      // 4. Scan Inline Styles & CSS Stylesheets
      for (const styleText of tabData.inlineStyles || []) {
        if (this.secretScanner) {
          discoveredSecrets.push(...this.secretScanner.scan(styleText, effectivePageUrl, 'css'));
        }
        if (this.supplyChainScanner) {
          discoveredSupplyChain.push(...this.supplyChainScanner.scan(styleText, effectivePageUrl, 'css'));
        }
        discoveredInItem.push(...this.extractUrlsFromCss(styleText, effectivePageUrl));
        if (typeof KatanaSecretScanner !== 'undefined') {
          const maps = KatanaSecretScanner.extractSourceMapUrls(styleText, effectivePageUrl);
          sourceMapUrlsToFetch.push(...maps);
        }
      }

      // Process External CSS Stylesheets
      const cssFiles = (tabData.cssSources || [])
        .map(c => this.normalizeUrl(c, effectivePageUrl))
        .filter(u => u && this.isInScope(u, effectiveSeedUrl) && !this.visitedUrls.has(u));

      if (cssFiles.length > 0) {
        const cssToFetch = cssFiles.slice(0, 10);
        cssToFetch.forEach(u => this.visitedUrls.add(u));
        const cssPromises = cssToFetch.map(async (cssUrl) => {
          try {
            const resp = await this.fetchWithTimeout(cssUrl, { timeout: 4000 });
            if (resp && resp.ok) {
              const cssText = await resp.text();
              if (this.secretScanner) {
                discoveredSecrets.push(...this.secretScanner.scan(cssText, cssUrl, 'css'));
              }
              if (this.supplyChainScanner) {
                discoveredSupplyChain.push(...this.supplyChainScanner.scan(cssText, cssUrl, 'css'));
              }
              discoveredInItem.push(...this.extractUrlsFromCss(cssText, cssUrl));
              if (typeof KatanaSecretScanner !== 'undefined') {
                const maps = KatanaSecretScanner.extractSourceMapUrls(cssText, cssUrl);
                sourceMapUrlsToFetch.push(...maps);
              }
            }
          } catch {}
        });
        await Promise.allSettled(cssPromises);
      }

      // Process HTML links
      for (const href of tabData.htmlLinks) {
        const normalized = this.normalizeUrl(href, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: 'html-link', sourceUrl: effectivePageUrl });
      }

      // Process Script sources
      for (const src of tabData.scriptSources) {
        const normalized = this.normalizeUrl(src, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: 'script-src', sourceUrl: effectivePageUrl });
      }

      // Process Form actions
      for (const f of tabData.formActions) {
        const normalized = this.normalizeUrl(f.action, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: `form-action[${f.method}]`, sourceUrl: effectivePageUrl });
      }

      // Process Data-* endpoints
      for (const d of tabData.dataEndpoints) {
        const normalized = this.normalizeUrl(d.value, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: `attr-${d.name}`, sourceUrl: effectivePageUrl });
      }

      // Process Live Network Resources
      for (const res of tabData.networkResources) {
        const normalized = this.normalizeUrl(res.name, effectivePageUrl);
        if (normalized) {
          const resType = res.initiatorType === 'xmlhttprequest' || res.initiatorType === 'fetch'
            ? 'network-api'
            : res.initiatorType === 'script'
              ? 'script-bundle'
              : 'network-resource';
          discoveredInItem.push({ url: normalized, type: resType, sourceUrl: effectivePageUrl });
        }
      }

      // Process Meta Tag Links
      for (const metaVal of tabData.metaLinks || []) {
        const normalized = this.normalizeUrl(metaVal, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: 'meta-link', sourceUrl: effectivePageUrl });
      }

      // ── EARLY ENQUEUE: Phase A ───────────────────────────────────────────────
      // Immediately enqueue navigable in-scope links from fast DOM extraction
      // BEFORE the slow phases (JS bundle fetching, button clicking, source maps).
      // This guarantees depth traversal begins even if a later phase is slow or hangs.
      for (const d of discoveredInItem) {
        if (!d.url || this.shouldIgnoreExtension(d.url)) continue;
        const canonical = this.canonicalUrl(d.url);
        if (!canonical) continue;
        if (this.isInScope(canonical, effectiveSeedUrl) &&
            depth < this.config.maxDepth &&
            this.isNavigableInTab(canonical) &&
            !this.visitedUrls.has(canonical) &&
            !this.enqueuedUrls.has(canonical)) {
          this.enqueuedUrls.add(canonical);
          this.queue.push({
            url: canonical,
            seedUrl: effectiveSeedUrl,
            depth: depth + 1,
            targetId: null
          });
          this.log('inf', `[Early Queue] [Depth ${depth + 1}/${this.config.maxDepth}] ${canonical}`);
        }
      }
    }

    // 5. Automated Button Clicking & Interactive DOM Exploration
    if (this.config.autoClickButtons) {
      try {
        const clickPromise = chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: katanaInTabClickExplorationScript,
          args: [this.config.maxButtonClicks || 8]
        });

        const clickTimeout = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Button exploration timeout')), 1800)
        );

        const clickResults = await Promise.race([clickPromise, clickTimeout]);
        const clickData = clickResults?.[0]?.result;
        if (clickData) {
          let buttonUrlsCount = 0;

          // Intercepted Fetch/XHR dynamic API calls
          for (const reqUrl of clickData.interceptedRequests || []) {
            const normalized = this.normalizeUrl(reqUrl, effectivePageUrl);
            if (normalized) {
              discoveredInItem.push({ url: normalized, type: 'button-click-api', sourceUrl: effectivePageUrl });
              buttonUrlsCount++;
            }
          }

          // Newly exposed DOM links (modals, dropdowns, tabs)
          for (const domUrl of clickData.newDomLinks || []) {
            const normalized = this.normalizeUrl(domUrl, effectivePageUrl);
            if (normalized) {
              discoveredInItem.push({ url: normalized, type: 'button-click-dom', sourceUrl: effectivePageUrl });
              buttonUrlsCount++;
            }
          }

          // Single-page application route transitions
          for (const navUrl of clickData.navigatedRoutes || []) {
            const normalized = this.normalizeUrl(navUrl, effectivePageUrl);
            if (normalized) {
              discoveredInItem.push({ url: normalized, type: 'button-click-nav', sourceUrl: effectivePageUrl });
              buttonUrlsCount++;
            }
          }

          if (clickData.clickedCount > 0) {
            this.log('inf', `[Button-Clicker] Clicked ${clickData.clickedCount} buttons, discovered ${buttonUrlsCount} dynamic endpoints!`);
          }
        }
      } catch (err) {
        this.log('wrn', `Button exploration notice for ${url}: ${err.message}`);
      }
    }

    // 6. Parallel Deep JS Crawling: Fetch and inspect external .js files concurrently
    if (this.config.crawlJavascript) {
      const jsFiles = discoveredInItem.filter(d =>
        (d.type === 'script-src' || d.type === 'script-bundle' || d.url.endsWith('.js')) &&
        this.isInScope(d.url, effectiveSeedUrl)
      );

      const jsFilesToFetch = jsFiles.slice(0, 15).filter(j => !this.visitedUrls.has(j.url));
      jsFilesToFetch.forEach(j => this.visitedUrls.add(j.url));

      if (jsFilesToFetch.length > 0) {
        this.log('inf', `[Katana-JS] Parallel spidering ${jsFilesToFetch.length} external JS bundles...`);
        const jsPromises = jsFilesToFetch.map(async (jsItem) => {
          try {
            const jsResp = await this.fetchWithTimeout(jsItem.url, { timeout: 4500 });
            if (jsResp && jsResp.ok) {
              const jsText = await jsResp.text();
              const endpoints = this.extractEndpointsFromJs(jsText, jsItem.url);
              discoveredInItem.push(...endpoints);

              // Secret scan of external JS bundle
              if (this.secretScanner) {
                discoveredSecrets.push(...this.secretScanner.scan(jsText, jsItem.url, 'js-bundle'));
              }
              if (this.supplyChainScanner) {
                discoveredSupplyChain.push(...this.supplyChainScanner.scan(jsText, jsItem.url, 'js-bundle'));
              }

              // Extract sourcemap references (.js.map)
              if (typeof KatanaSecretScanner !== 'undefined') {
                const maps = KatanaSecretScanner.extractSourceMapUrls(jsText, jsItem.url);
                if (maps.length > 0) {
                  sourceMapUrlsToFetch.push(...maps);
                } else if (jsItem.url.endsWith('.js')) {
                  sourceMapUrlsToFetch.push(jsItem.url + '.map');
                }
              }

              if (this.config.subdomainCrawl) {
                const jsSubdomains = this.extractSubdomainsFromText(jsText, effectiveSeedUrl);
                if (jsSubdomains.length > 0) {
                  discoveredInItem.push(...jsSubdomains);
                }
              }
            }
          } catch {}
        });
        await Promise.allSettled(jsPromises);
      }
    }

    // 6b. Deep Source Map Spidering (.js.map and .css.map):
    // Fetches original unminified source code arrays & audits them for secrets & endpoints
    if (sourceMapUrlsToFetch.length > 0) {
      const uniqueMaps = [...new Set(sourceMapUrlsToFetch)]
        .filter(m => m && this.isInScope(m, effectiveSeedUrl) && !this.visitedUrls.has(m))
        .slice(0, 10);

      uniqueMaps.forEach(m => this.visitedUrls.add(m));

      if (uniqueMaps.length > 0) {
        this.log('inf', `[Katana-Map] Parallel spidering ${uniqueMaps.length} source maps (.js.map)...`);
        const mapPromises = uniqueMaps.map(async (mapUrl) => {
          try {
            const mapResp = await this.fetchWithTimeout(mapUrl, { timeout: 4500 });
            if (mapResp && mapResp.ok) {
              const mapText = await mapResp.text();
              if (mapText.includes('"sources"') || mapText.includes('"version"')) {
                this.log('inf', `[Katana-Map] Auditing source map: ${mapUrl}`);
                discoveredInItem.push({ url: mapUrl, type: 'source-map', sourceUrl: effectivePageUrl });

                // Deep secret scanning on original unminified source code!
                if (this.secretScanner) {
                  discoveredSecrets.push(...this.secretScanner.scan(mapText, mapUrl, 'source-map'));
                }
                if (this.supplyChainScanner) {
                  discoveredSupplyChain.push(...this.supplyChainScanner.scan(mapText, mapUrl, 'source-map'));
                }

                // Extract endpoints from source map!
                const mapEndpoints = this.extractEndpointsFromJs(mapText, mapUrl);
                discoveredInItem.push(...mapEndpoints);
              }
            }
          } catch {}
        });
        await Promise.allSettled(mapPromises);
      }
    }

    // 7. Check robots.txt and sitemap.xml on depth 0 and 1 seeds
    if (depth <= 1 && this.config.parseRobotsAndSitemaps) {
      try {
        const robotsUrls = await this.fetchRobotsAndSitemaps(url);
        discoveredInItem.push(...robotsUrls);
      } catch {}
    }

    // 8. Subdomain extraction from page content if enabled
    if (this.config.subdomainCrawl) {
      const pageText = (tabData?.htmlLinks?.join(' ') || '') + ' ' + (tabData?.inlineScripts?.join(' ') || '');
      const domSubdomains = this.extractSubdomainsFromText(pageText, seedUrl);
      discoveredInItem.push(...domSubdomains);
    }

    // 9. Canonical Deduplication, Scope-Tagging, and Recursive Enqueuing
    const processedDiscovered = [];
    for (const d of discoveredInItem) {
      if (this.shouldIgnoreExtension(d.url)) continue;

      const canonical = this.canonicalUrl(d.url);
      if (!canonical) continue;
      d.url = canonical;

      const inScope = this.isInScope(canonical, effectiveSeedUrl);
      d.scope = inScope ? 'in-scope' : 'out-of-scope';
      d.targetUrl = effectiveSeedUrl;
      d.depth = depth;

      // Deduplicate within the current crawl session
      if (this.sessionDiscoveredUrls.has(canonical)) {
        this.duplicatesFiltered++;
      } else {
        this.sessionDiscoveredUrls.add(canonical);
        processedDiscovered.push(d);
      }

      // Enqueue in-scope links for further depth:
      // CRITICAL: Only enqueue NAVIGABLE pages in the single tab (NOT raw .js, .css, or media files!)
      // This loads actual HTML pages, web endpoints, and subdomains in the tab to find the maximum possible URLs!
      if (inScope &&
          depth < this.config.maxDepth &&
          this.isNavigableInTab(canonical)) {

        if (!this.visitedUrls.has(canonical) && !this.enqueuedUrls.has(canonical)) {
          this.enqueuedUrls.add(canonical);
          this.queue.push({
            url: canonical,
            seedUrl: effectiveSeedUrl,
            depth: depth + 1,
            targetId: null
          });
          this.log('inf', `[Open in Tab Queued] [Depth ${depth + 1}/${this.config.maxDepth}] ${canonical}`);
        }
      }
    }

    this.updateProgress();

    const addedCount = await this.storage.addDiscoveredUrls(processedDiscovered);
    this.totalDiscoveredInSession += processedDiscovered.length;

    // Persist discovered secrets to database & notify dashboard
    if (this.secretScanner && discoveredSecrets.length > 0) {
      const res = await this.storage.saveSecrets(discoveredSecrets);
      const newCount = (typeof res === 'object') ? (res.newCount || 0) : (res || 0);
      const updatedCount = (typeof res === 'object') ? (res.updatedCount || 0) : 0;
      if (newCount > 0 || updatedCount > 0) {
        this.totalSecretsInSession += newCount;
        if (newCount > 0) {
          this.log('wrn', `[SECRETS] Discovered ${newCount} new unique sensitive credential(s) on ${effectivePageUrl}!${updatedCount > 0 ? ` (+${updatedCount} location updates)` : ''}`);
        } else {
          this.log('info', `[SECRETS] Linked existing secret(s) to new location on ${effectivePageUrl} (+${updatedCount} locations)`);
        }
        if (this.onSecretFound) {
          this.onSecretFound(discoveredSecrets);
        }
      }
    }

    // Persist discovered supply chain packages & configs to database & notify dashboard
    if (this.supplyChainScanner && discoveredSupplyChain.length > 0) {
      try {
        const supplyRes = await this.storage.saveSupplyChainFindings(discoveredSupplyChain);
        const newSupplyCount = (typeof supplyRes === 'object') ? (supplyRes.newCount || 0) : (supplyRes || 0);
        const updatedSupplyCount = (typeof supplyRes === 'object') ? (supplyRes.updatedCount || 0) : 0;

        if (newSupplyCount > 0 || updatedSupplyCount > 0) {
          this.totalSupplyChainInSession += newSupplyCount;
          if (newSupplyCount > 0) {
            this.log('inf', `[SUPPLY CHAIN] Extracted ${newSupplyCount} new package dependency(ies) on ${effectivePageUrl}!${updatedSupplyCount > 0 ? ` (+${updatedSupplyCount} locations)` : ''}`);
          }
          if (this.onSupplyChainFinding) {
            this.onSupplyChainFinding(discoveredSupplyChain);
          }
        }

        // Asynchronously evaluate packages in background queue (OSV & dependency confusion checks)
        // Completely non-blocking so crawler velocity stays at maximum speed!
        this.supplyChainScanner.queueForEvaluation(discoveredSupplyChain, async (evaluated) => {
          if (!evaluated) return;
          await this.storage.saveSupplyChainFindings([evaluated]);
          if (evaluated.isUnregistered) {
            this.log('wrn', `[SUPPLY CHAIN ALERT] UNREGISTERED PACKAGE detected: "${evaluated.name}" (${evaluated.ecosystem}) - Dependency Confusion Attack Risk!`);
          } else if (evaluated.advisoriesCount > 0) {
            this.log('wrn', `[SUPPLY CHAIN ALERT] Vulnerable package detected: "${evaluated.name}" has ${evaluated.advisoriesCount} known CVE advisories!`);
          }
          if (this.onSupplyChainFinding) {
            this.onSupplyChainFinding([evaluated]);
          }
        });
      } catch (err) {
        console.warn('Supply chain processing error:', err);
      }
    }

    if (targetId) {
      await this.storage.updateTarget(targetId, {
        status: 'completed',
        crawledAt: Date.now(),
        discoveredCount: addedCount
      });
    }

    this.log('inf', `Extracted ${discoveredInItem.length} endpoints (${addedCount} new unique, ${this.duplicatesFiltered} total dupes skipped) from ${url}`);

    if (this.onUrlFound) {
      this.onUrlFound(processedDiscovered);
    }
  }

  /**
   * Helper that pauses crawler execution until CAPTCHA is solved
   */
  async waitForCaptchaResolution(tabId) {
    return new Promise((resolve) => {
      let isResolved = false;
      let safetyTimer = null;
      let interval = null;

      const finish = () => {
        if (!isResolved) {
          isResolved = true;
          if (safetyTimer) clearTimeout(safetyTimer);
          if (interval) clearInterval(interval);
          this.isWaitingForCaptcha = false;
          this.captchaResolver = null;
          resolve();
        }
      };

      // Check every 2 seconds if the challenge page navigated or resolved
      interval = setInterval(async () => {
        if (!this.isRunning || !this.isWaitingForCaptcha) {
          finish();
          return;
        }

        try {
          const res = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => {
              const title = (document.title || '').toLowerCase();
              const bodyText = (document.body ? document.body.innerText || '' : '').toLowerCase().slice(0, 3000);
              const hasNormalContent = bodyText.length > 500 && !title.includes('just a moment') && !title.includes('attention required');
              if (hasNormalContent) return false;

              const isCf = title.includes('just a moment') ||
                           title.includes('attention required!') ||
                           document.querySelector('#cf-challenge-running') !== null ||
                           (document.querySelector('#challenge-form') !== null && title.includes('moment'));
              const isBlocking = isCf || (
                (title.includes('captcha') || title.includes('security check') || title.includes('bot verification') || title.includes('are you human')) &&
                (bodyText.includes('verify you are human') || bodyText.includes('please solve the challenge') || bodyText.includes('confirm you are not a robot'))
              );
              return isBlocking;
            }
          });

          const stillHasCaptcha = res?.[0]?.result;
          if (!stillHasCaptcha) {
            finish();
          }
        } catch {
          // If execution fails, tab may have navigated to normal page
          finish();
        }
      }, 1500);

      // Auto-resume after 15s safety timeout so crawler never hangs indefinitely
      safetyTimer = setTimeout(() => {
        this.log('wrn', '[CAPTCHA] Resolution wait timed out after 15s. Automatically resuming crawl...');
        finish();
      }, 15000);

      this.captchaResolver = finish;
    });
  }

  resolveCaptchaManually() {
    this.isWaitingForCaptcha = false;
    if (this.captchaResolver) {
      this.captchaResolver();
      this.captchaResolver = null;
    }
  }

  skipCurrentTarget() {
    this.isWaitingForCaptcha = false;
    if (this.currentCaptchaTarget) {
      this.log('wrn', `[SKIP] Skipped target ${this.currentCaptchaTarget.url} by user request`);
      this.currentCaptchaTarget = null;
    }
    if (this.captchaResolver) {
      this.captchaResolver();
      this.captchaResolver = null;
    }
  }

  // =========================================================================
  // MAIN RUNNER
  // =========================================================================

  async start(targets) {
    if (this.isRunning) return;

    this.isRunning = true;
    this.isPaused = false;
    this.isWaitingForCaptcha = false;
    this.abortController = new AbortController();
    this.startTime = Date.now();
    this.crawledCount = 0;
    this.errorCount = 0;
    this.totalDiscoveredInSession = 0;

    this.log('inf', `=================================================================`);
    this.log('inf', `Katana Engine Started in [${this.config.mode.toUpperCase()}] mode`);
    this.log('inf', `Targets: ${targets.length} seeds | Depth: ${this.config.maxDepth} | Scope: ${this.config.scopeMode}`);
    if (this.config.mode === 'single-tab') {
      this.log('inf', `Single-Tab Browser Active: JavaScript will be executed & CAPTCHAs can be solved!`);
    }
    this.log('inf', `=================================================================`);

    if (this.onStateChange) this.onStateChange('running');

    this.queue = [];
    this.enqueuedUrls = new Set();
    this.visitedUrls = new Set();
    this.sessionDiscoveredUrls = new Set();
    this.subdomainsDiscovered = new Set();
    this.duplicatesFiltered = 0;

    for (const t of targets) {
      const canonical = this.canonicalUrl(t.url || t);
      if (canonical && !this.enqueuedUrls.has(canonical)) {
        this.enqueuedUrls.add(canonical);
        this.queue.push({
          url: canonical,
          seedUrl: canonical,
          targetId: t.id || null,
          depth: 0
        });
      }
    }

    this.updateProgress();

    if (this.config.mode === 'single-tab') {
      // Single tab crawler runner (strictly sequential on one browser tab)
      await this.runSingleTabCrawler();
    } else {
      // Fast background fetch runner
      const workerPromises = [];
      for (let i = 0; i < this.config.concurrency; i++) {
        workerPromises.push(this.runFetchWorker(i + 1));
      }
      await Promise.all(workerPromises);
    }

    this.isRunning = false;
    this.log('inf', `Crawl complete. Visited: ${this.crawledCount}, Total Discovered: ${this.totalDiscoveredInSession}, Errors: ${this.errorCount}`);
    if (this.onStateChange) this.onStateChange('stopped');
  }

  async runSingleTabCrawler() {
    this.activeWorkers = 1;

    while (this.isRunning && this.queue.length > 0) {
      if (this.isPaused) {
        await new Promise(r => setTimeout(r, 400));
        continue;
      }

      const item = this.queue.shift();
      if (!item) continue;

      if (this.visitedUrls.has(item.url)) continue;
      this.visitedUrls.add(item.url);

      this.updateProgress();

      try {
        await this.crawlItemSingleTab(item);
      } catch (err) {
        this.errorCount++;
        this.log('wrn', `Error crawling ${item.url}: ${err.message}`);
        if (item.targetId) {
          await this.storage.updateTarget(item.targetId, { status: 'failed', error: err.message });
        }
      } finally {
        this.crawledCount++;
        this.updateProgress();

        if (this.config.delayMs > 0) {
          await new Promise(r => setTimeout(r, this.config.delayMs));
        }
      }
    }

    this.activeWorkers = 0;
  }

  async runFetchWorker(workerId) {
    let emptyChecks = 0;
    while (this.isRunning) {
      if (this.isPaused) {
        await new Promise(r => setTimeout(r, 400));
        continue;
      }

      if (this.queue.length === 0) {
        if (this.activeWorkers === 0) {
          emptyChecks++;
          if (emptyChecks >= 4) break; // Grace period before worker exits
          await new Promise(r => setTimeout(r, 250));
          continue;
        }
        await new Promise(r => setTimeout(r, 200));
        continue;
      }

      emptyChecks = 0;
      const item = this.queue.shift();
      if (!item) continue;

      if (this.visitedUrls.has(item.url)) continue;
      this.visitedUrls.add(item.url);

      this.activeWorkers++;
      this.updateProgress();

      try {
        await this.crawlItemFetch(item);
      } catch (err) {
        this.errorCount++;
        this.log('wrn', `Failed to crawl ${item.url}: ${err.message}`);
      } finally {
        this.activeWorkers--;
        this.crawledCount++;
        this.updateProgress();

        if (this.config.delayMs > 0) {
          await new Promise(r => setTimeout(r, this.config.delayMs));
        }
      }
    }
  }

  async crawlItemFetch(item) {
    const { url, seedUrl, depth, targetId } = item;
    const resp = await this.fetchWithTimeout(url);
    const body = await resp.text();
    const contentType = resp.headers.get('content-type') || '';

    let discovered = [];
    if (contentType.includes('html') || !contentType) {
      discovered.push(...this.extractUrlsFromHtml(body, url));
    } else {
      discovered.push(...this.extractEndpointsFromJs(body, url));
    }

    const processed = [];
    for (const d of discovered) {
      if (this.shouldIgnoreExtension(d.url)) continue;
      const canonical = this.canonicalUrl(d.url);
      if (!canonical) continue;
      d.url = canonical;

      const inScope = this.isInScope(canonical, seedUrl);
      d.scope = inScope ? 'in-scope' : 'out-of-scope';
      d.targetUrl = seedUrl;
      d.depth = depth;

      if (this.sessionDiscoveredUrls.has(canonical)) {
        this.duplicatesFiltered++;
      } else {
        this.sessionDiscoveredUrls.add(canonical);
        processed.push(d);
      }

      if (inScope && depth < this.config.maxDepth && this.isNavigableInTab(canonical)) {
        if (!this.visitedUrls.has(canonical) && !this.enqueuedUrls.has(canonical)) {
          this.enqueuedUrls.add(canonical);
          this.queue.push({
            url: canonical,
            seedUrl: seedUrl,
            depth: depth + 1,
            targetId: null
          });
        }
      }
    }

    const added = await this.storage.addDiscoveredUrls(processed);
    this.totalDiscoveredInSession += processed.length;
    if (this.onUrlFound) this.onUrlFound(processed);

    // Secret scanning in Fast-Fetch mode
    if (this.secretScanner) {
      const srcType = contentType.includes('javascript') ? 'js-bundle' : contentType.includes('css') ? 'css' : 'html';
      const sec = this.secretScanner.scan(body, url, srcType);
      if (sec.length > 0) {
        const res = await this.storage.saveSecrets(sec);
        const newCount = (typeof res === 'object') ? (res.newCount || 0) : (res || 0);
        const updatedCount = (typeof res === 'object') ? (res.updatedCount || 0) : 0;
        if (newCount > 0 || updatedCount > 0) {
          this.totalSecretsInSession += newCount;
          if (newCount > 0) {
            this.log('wrn', `[SECRETS] Discovered ${newCount} new unique sensitive findings on ${url}!${updatedCount > 0 ? ` (+${updatedCount} locations)` : ''}`);
          }
          if (this.onSecretFound) this.onSecretFound(sec);
        }
      }
    }

    // Supply chain scanning in Fast-Fetch mode
    if (this.supplyChainScanner) {
      const srcType = contentType.includes('javascript') ? 'js-bundle' : contentType.includes('css') ? 'css' : 'html';
      const pkgs = this.supplyChainScanner.scan(body, url, srcType);
      if (pkgs.length > 0) {
        try {
          const supplyRes = await this.storage.saveSupplyChainFindings(pkgs);
          const newSupplyCount = (typeof supplyRes === 'object') ? (supplyRes.newCount || 0) : (supplyRes || 0);
          const updatedSupplyCount = (typeof supplyRes === 'object') ? (supplyRes.updatedCount || 0) : 0;
          if (newSupplyCount > 0 || updatedSupplyCount > 0) {
            this.totalSupplyChainInSession += newSupplyCount;
            if (newSupplyCount > 0) {
              this.log('inf', `[SUPPLY CHAIN] Extracted ${newSupplyCount} package(s) on ${url}!`);
            }
            if (this.onSupplyChainFinding) this.onSupplyChainFinding(pkgs);
          }

          this.supplyChainScanner.queueForEvaluation(pkgs, async (evaluated) => {
            if (!evaluated) return;
            await this.storage.saveSupplyChainFindings([evaluated]);
            if (evaluated.isUnregistered) {
              this.log('wrn', `[SUPPLY CHAIN ALERT] UNREGISTERED PACKAGE detected: "${evaluated.name}" - Dependency Confusion Risk!`);
            } else if (evaluated.advisoriesCount > 0) {
              this.log('wrn', `[SUPPLY CHAIN ALERT] Vulnerable package detected: "${evaluated.name}" has ${evaluated.advisoriesCount} CVEs!`);
            }
            if (this.onSupplyChainFinding) this.onSupplyChainFinding([evaluated]);
          });
        } catch (e) {}
      }
    }
  }

  pause() {
    this.isPaused = true;
    this.log('inf', 'Crawler paused');
    if (this.onStateChange) this.onStateChange('paused');
  }

  resume() {
    this.isPaused = false;
    this.resolveCaptchaManually();
    this.log('inf', 'Crawler resumed');
    if (this.onStateChange) this.onStateChange('running');
  }

  stop() {
    this.isRunning = false;
    this.isPaused = false;
    this.resolveCaptchaManually();
    if (this.abortController) this.abortController.abort();
    this.queue = [];
    this.log('inf', 'Crawler stopped by user');
    if (this.onStateChange) this.onStateChange('stopped');
  }

  updateProgress() {
    const elapsed = this.startTime ? (Date.now() - this.startTime) / 1000 : 0;
    const rps = elapsed > 0 ? (this.crawledCount / elapsed).toFixed(1) : '0.0';

    const progressData = {
      crawled: this.crawledCount,
      crawledTargets: this.crawledCount,
      totalTargets: this.crawledCount + this.queue.length,
      queueLength: this.queue.length,
      activeWorkers: this.activeWorkers,
      totalDiscovered: this.totalDiscoveredInSession,
      duplicatesFiltered: this.duplicatesFiltered,
      subdomainsCount: this.subdomainsDiscovered.size,
      subdomains: this.subdomainsDiscovered.size,
      errors: this.errorCount,
      rps: rps
    };

    if (this.onProgress) {
      this.onProgress(progressData);
    }
    if (this.onStatsUpdate) {
      this.onStatsUpdate(progressData);
    }
  }
}

// Global engine singleton
if (typeof window !== 'undefined') {
  window.KatanaCrawlerEngine = KatanaCrawlerEngine;
  window.katanaEngine = new KatanaCrawlerEngine(window.katanaStorage);
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KatanaCrawlerEngine };
}
