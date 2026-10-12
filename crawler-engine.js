/**
 * Katana Web Crawler - Core Engine
 * Implements ProjectDiscovery Katana-style endpoint parsing, single-tab interactive crawling
 * (with CAPTCHA detection and solving), deep JS bundle analysis, and LinkFinder regex extraction.
 */

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
      maxDepth: 3,        // Follow discovered in-scope endpoints in the browser tab
      timeout: 6000,      // Fast 6s timeout per request/tab load
      tabRenderDelay: 400, // Fast 400ms delay after DOM load for JS hydration
      scopeMode: 'same-domain', // 'same-domain', 'same-root', 'regex', 'all'
      scopeRegex: '',
      subdomainCrawl: true,     // Crawl discovered subdomains (*.example.com) when enabled
      openFoundUrlsInTab: true, // Automatically open discovered URLs in the single tab (excluding static assets)
      crawlJavascript: true,    // Deep JS crawl: Fetch & regex-extract external JS bundles
      autoClickButtons: true,   // Automatically click buttons & interactive elements to discover dynamic endpoints
      maxButtonClicks: 10,      // Maximum 10 buttons per page for rapid exploration
      parseRobotsAndSitemaps: true, // Check robots.txt and sitemap.xml
      ignoreFileExtensions: ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip'],
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Katana/1.1',
      delayMs: 100 // Rapid 100ms delay between requests
    };

    // State
    this.queue = [];
    this.enqueuedUrls = new Set(); // Strict queue deduplication set
    this.visitedUrls = new Set();  // Visited URLs set
    this.subdomainsDiscovered = new Set(); // Unique discovered subdomains
    this.duplicatesFiltered = 0;   // Count of duplicate URLs filtered
    this.totalDiscoveredInSession = 0;
    this.crawledCount = 0;
    this.errorCount = 0;
    this.startTime = null;
    this.activeWorkers = 0;
    this.currentCaptchaTarget = null;
    this.captchaCheckInterval = null;

    // Callbacks
    this.onLog = null;
    this.onProgress = null;
    this.onUrlFound = null;
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

      if (this.config.scopeMode === 'regex' && this.config.scopeRegex) {
        const re = new RegExp(this.config.scopeRegex, 'i');
        return re.test(candidateUrl);
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
          'User-Agent': this.config.userAgent,
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

  /**
   * Fast-navigate the single tab: Resolves as soon as DOM is interactive/loaded
   * or complete, preventing waiting for slow trackers/ads/media!
   */
  async navigateTabAndWait(tabId, url, timeoutMs = 5000) {
    return new Promise((resolve) => {
      let isResolved = false;
      let timer = null;
      let pollInterval = null;

      const finish = () => {
        if (!isResolved) {
          isResolved = true;
          if (timer) clearTimeout(timer);
          if (pollInterval) clearInterval(pollInterval);
          chrome.tabs.onUpdated.removeListener(onUpdatedListener);
          resolve(null);
        }
      };

      const onUpdatedListener = (updatedTabId, changeInfo, tab) => {
        if (updatedTabId === tabId) {
          if (changeInfo.status === 'complete' || (tab && tab.status === 'complete')) {
            finish();
          }
        }
      };

      // Fast-poll document.readyState every 200ms: proceed as soon as DOM is interactive!
      pollInterval = setInterval(async () => {
        try {
          const res = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => document.readyState
          });
          const state = res?.[0]?.result;
          if (state === 'interactive' || state === 'complete') {
            finish();
          }
        } catch {}
      }, 200);

      // Max hard timeout: 5s max (prevents hanging on slow tracking pixels/ads)
      timer = setTimeout(finish, Math.min(timeoutMs, 5000));

      chrome.tabs.onUpdated.addListener(onUpdatedListener);
      chrome.tabs.update(tabId, { url }).catch(finish);
    });
  }

  /**
   * In-tab content inspection script
   * Runs in the live browser tab: checks for CAPTCHA/bot challenges,
   * extracts live DOM links, form actions, scripts, data-attributes,
   * and browser performance network entries!
   */
  static inTabExtractionScript() {
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
      rawHtml: ''
    };

    // 1. CAPTCHA & Cloudflare Bot Challenge Detection (Checks for real blocking interstitials)
    const title = (document.title || '').toLowerCase();
    const bodyText = (document.body ? document.body.innerText || '' : '').toLowerCase().slice(0, 3000);

    const isCloudflare = title.includes('just a moment') ||
                         title.includes('attention required! | cloudflare') ||
                         document.querySelector('#challenge-form') !== null ||
                         document.querySelector('#cf-challenge-running') !== null ||
                         document.querySelector('.cf-turnstile-wrapper') !== null ||
                         (document.querySelector('iframe[src*="challenges.cloudflare.com"]') !== null && (title.includes('just a moment') || title.includes('cloudflare')));

    // Only flag true blocking challenge pages! NOT pages with invisible background reCAPTCHA widgets!
    const isBlockingCaptcha = (
      (title.includes('captcha') || title.includes('security check') || title.includes('bot verification') || title.includes('robot')) &&
      (document.querySelector('.g-recaptcha, .h-captcha') !== null || bodyText.includes('verify you are human') || bodyText.includes('please solve the challenge'))
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

    // 2. Extract DOM links (a, link, area, iframe, embed, object, audio, video, source)
    document.querySelectorAll('a[href], link[href], area[href], iframe[src], embed[src], object[data], source[src], video[src], audio[src]').forEach(el => {
      const val = el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('data');
      if (val) result.htmlLinks.push(val);
    });

    // 3. Extract Script sources
    document.querySelectorAll('script[src]').forEach(el => {
      const src = el.getAttribute('src');
      if (src) result.scriptSources.push(src);
    });

    // 4. Extract Form actions & formactions
    document.querySelectorAll('form[action], input[formaction], button[formaction]').forEach(el => {
      const action = el.getAttribute('action') || el.getAttribute('formaction') || '';
      const method = (el.getAttribute('method') || 'GET').toUpperCase();
      if (action) result.formActions.push({ action, method });
    });

    // 5. Extract Inline Scripts & JSON routing blobs (e.g. Next.js __NEXT_DATA__, Nuxt __NUXT__)
    document.querySelectorAll('script:not([src])').forEach(script => {
      const content = script.textContent || '';
      if (content.length > 5) {
        const type = (script.getAttribute('type') || '').toLowerCase();
        const id = (script.id || '').toLowerCase();
        if (type.includes('json') || id.includes('next') || id.includes('nuxt')) {
          result.jsonBlobs.push(content);
        } else {
          result.inlineScripts.push(content);
        }
      }
    });

    // 6. Extract Meta tag URLs
    document.querySelectorAll('meta[content*="/"], meta[content*="http"]').forEach(m => {
      const c = m.getAttribute('content');
      if (c && c.length > 1) result.metaLinks.push(c);
    });

    // 7. Extract HTML Comments (where developers hide staging URLs, API keys, test routes)
    try {
      const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT);
      let curNode;
      let count = 0;
      while ((curNode = iterator.nextNode()) && count < 250) {
        if (curNode.nodeValue) result.htmlComments.push(curNode.nodeValue);
        count++;
      }
    } catch(e) {}

    // 8. Extract data-* attributes with paths/URLs
    const pathAttrRegex = /^(?:data-(?:url|href|src|path|endpoint|route|api|target)|action|formaction|cite|ping|poster|manifest)$/i;
    document.querySelectorAll('*').forEach(el => {
      for (const attr of el.attributes) {
        if (pathAttrRegex.test(attr.name) && attr.value) {
          result.dataEndpoints.push({ name: attr.name, value: attr.value });
        }
      }
    });

    // 9. Extract network requests recorded by browser Performance API!
    try {
      const resources = performance.getEntriesByType('resource');
      resources.forEach(r => {
        if (r.name && !r.name.startsWith('data:') && !r.name.startsWith('blob:')) {
          result.networkResources.push({
            name: r.name,
            initiatorType: r.initiatorType || 'resource'
          });
        }
      });
    } catch {}

    // 10. Capture Raw HTML for deep Katana regex parsing
    try {
      result.rawHtml = document.documentElement.outerHTML.slice(0, 1500000);
    } catch(e) {}

    return result;
  }

  /**
   * High-speed automated button clicking & interaction explorer
   */
  static inTabClickExplorationScript(maxClicks = 10) {
    return new Promise((resolve) => {
      const clickedResults = {
        clickedCount: 0,
        interceptedRequests: [],
        newDomLinks: [],
        navigatedRoutes: []
      };

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

      const destructiveRegex = /log\s*out|sign\s*out|delete|remove|destroy|trash|cancel\s*account/i;
      const selectors = [
        'button',
        'input[type="button"]',
        'input[type="submit"]',
        '[role="button"]',
        '[role="tab"]',
        '[role="menuitem"]',
        'a[href="#"]',
        'a[href^="javascript:"]',
        '.btn',
        '.button',
        '.tab',
        '.nav-link'
      ];

      const elements = document.querySelectorAll(selectors.join(', '));
      const candidates = [];

      for (const el of elements) {
        if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;

        const text = (el.innerText || el.value || el.title || el.getAttribute('aria-label') || '').trim();
        if (destructiveRegex.test(text)) continue;

        candidates.push(el);
        if (candidates.length >= maxClicks) break;
      }

      function cleanup() {
        try {
          window.fetch = originalFetch;
          XMLHttpRequest.prototype.open = originalXhrOpen;
          history.pushState = originalPushState;
          history.replaceState = originalReplaceState;

          document.querySelectorAll('a[href], link[href], form[action]').forEach(el => {
            const val = el.getAttribute('href') || el.getAttribute('action');
            if (val) clickedResults.newDomLinks.push(val);
          });

          performance.getEntriesByType('resource').forEach(r => {
            if (r.name && !r.name.startsWith('data:') && !r.name.startsWith('blob:')) {
              clickedResults.interceptedRequests.push(r.name);
            }
          });
        } catch(e) {}
      }

      if (candidates.length === 0) {
        cleanup();
        resolve(clickedResults);
        return;
      }

      let idx = 0;
      function clickNext() {
        if (idx >= candidates.length) {
          cleanup();
          resolve(clickedResults);
          return;
        }

        const el = candidates[idx++];
        try {
          clickedResults.clickedCount++;
          el.scrollIntoView({ behavior: 'instant', block: 'center' });
          el.click();
          el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
        } catch(e) {}

        setTimeout(clickNext, 35);
      }

      clickNext();
    });
  }

  /**
   * Crawl a single target URL using the dedicated browser tab
   */
  async crawlItemSingleTab(item) {
    const { url, seedUrl, depth, targetId } = item;
    this.log('inf', `[Browser Tab] Navigating [Depth ${depth}]: ${url}`);

    if (targetId) {
      await this.storage.updateTarget(targetId, { status: 'crawling' });
    }

    const tab = await this.ensureCrawlerTab();

    // 1. Navigate to target URL
    try {
      await this.navigateTabAndWait(tab.id, url, this.config.timeout);
    } catch (err) {
      this.log('wrn', `Navigation failed for ${url}: ${err.message}`);
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
        func: KatanaCrawlerEngine.inTabExtractionScript
      });
      tabData = injectionResults?.[0]?.result;
    } catch (err) {
      this.log('wrn', `Could not inspect tab content for ${url}: ${err.message}`);
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
          func: KatanaCrawlerEngine.inTabExtractionScript
        });
        tabData = reExtract?.[0]?.result;
      } catch {}
    }

    let discoveredInItem = [];
    const effectivePageUrl = tabData?.pageUrl || url;

    // Fallback: If in-tab DOM inspection returned null (e.g. extension permission denied on error page or CSP sandbox), fetch directly
    if (!tabData) {
      try {
        this.log('inf', `[Engine Fallback] In-tab execution unavailable for ${url}, spidering via background HTTP engine...`);
        const resp = await this.fetchWithTimeout(url, { timeout: 8000 });
        if (resp && resp.ok) {
          const bodyText = await resp.text();
          const fallbackUrls = this.extractUrlsFromHtml(bodyText, url);
          discoveredInItem.push(...fallbackUrls);
          this.log('inf', `[Engine Fallback] Extracted ${fallbackUrls.length} links via background spider for ${url}`);
        }
      } catch (err) {
        this.log('wrn', `Fallback fetch failed for ${url}: ${err.message}`);
      }
    }

    if (tabData) {
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

      // Process Live Network Resources (XHR/Fetch/JS Chunks executed by the browser)
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

      // Parse Inline Scripts with Katana Regex
      for (const scriptText of tabData.inlineScripts || []) {
        const jsEndpoints = this.extractEndpointsFromJs(scriptText, effectivePageUrl);
        discoveredInItem.push(...jsEndpoints);
      }

      // Parse Raw HTML Document Source with Katana Endpoint Regex (catches embedded routes & webpack strings)
      if (tabData.rawHtml) {
        const rawEndpoints = this.extractEndpointsFromJs(tabData.rawHtml, effectivePageUrl);
        discoveredInItem.push(...rawEndpoints);
      }

      // Parse Next.js / Nuxt JSON Blobs & Hydration States (finds hidden route manifests)
      for (const jsonStr of tabData.jsonBlobs || []) {
        const jsonEndpoints = this.extractEndpointsFromJs(jsonStr, effectivePageUrl);
        discoveredInItem.push(...jsonEndpoints);
      }

      // Parse HTML Comments for Hidden / Staging Endpoints
      for (const comment of tabData.htmlComments || []) {
        const commentEndpoints = this.extractEndpointsFromJs(comment, effectivePageUrl);
        discoveredInItem.push(...commentEndpoints);
        if (this.config.subdomainCrawl) {
          const commentSubs = this.extractSubdomainsFromText(comment, seedUrl);
          discoveredInItem.push(...commentSubs);
        }
      }

      // Process Meta Tag Links
      for (const metaVal of tabData.metaLinks || []) {
        const normalized = this.normalizeUrl(metaVal, effectivePageUrl);
        if (normalized) discoveredInItem.push({ url: normalized, type: 'meta-link', sourceUrl: effectivePageUrl });
      }
    }

    // 5. Automated Button Clicking & Interactive DOM Exploration
    if (this.config.autoClickButtons) {
      try {
        const clickResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: KatanaCrawlerEngine.inTabClickExplorationScript,
          args: [this.config.maxButtonClicks || 10]
        });

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
        this.log('wrn', `Button exploration warning for ${url}: ${err.message}`);
      }
    }

    // 6. Parallel Deep JS Crawling: Fetch and inspect external .js files concurrently
    if (this.config.crawlJavascript) {
      const jsFiles = discoveredInItem.filter(d =>
        (d.type === 'script-src' || d.type === 'script-bundle' || d.url.endsWith('.js')) &&
        this.isInScope(d.url, seedUrl)
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

              if (this.config.subdomainCrawl) {
                const jsSubdomains = this.extractSubdomainsFromText(jsText, seedUrl);
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

      const inScope = this.isInScope(canonical, seedUrl);
      d.scope = inScope ? 'in-scope' : 'out-of-scope';
      d.targetUrl = seedUrl;
      d.depth = depth;

      // Strict Deduplication Check
      if (this.visitedUrls.has(canonical) || this.storage.knownUrlSet.has(canonical)) {
        this.duplicatesFiltered++;
      } else {
        processedDiscovered.push(d);
      }

      // Enqueue in-scope links for further depth:
      // CRITICAL: Only enqueue NAVIGABLE pages in the single tab (NOT raw .js, .css, or media files!)
      // This loads actual HTML pages, web endpoints, and subdomains in the tab to find the maximum possible URLs!
      const canOpenInTab = (this.config.openFoundUrlsInTab !== false);
      if (inScope &&
          depth < this.config.maxDepth &&
          canOpenInTab &&
          this.isNavigableInTab(canonical)) {

        if (!this.visitedUrls.has(canonical) && !this.enqueuedUrls.has(canonical)) {
          this.enqueuedUrls.add(canonical);
          this.queue.push({
            url: canonical,
            seedUrl: seedUrl,
            depth: depth + 1,
            targetId: null
          });
          this.log('inf', `[Open in Tab Queued] [Depth ${depth + 1}/${this.config.maxDepth}] ${canonical}`);
        }
      }
    }

    this.updateProgress();

    const addedCount = await this.storage.addDiscoveredUrls(processedDiscovered);
    this.totalDiscoveredInSession += addedCount;

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
      // Check every 2.5 seconds if the challenge page navigated or resolved
      const interval = setInterval(async () => {
        if (!this.isRunning || !this.isWaitingForCaptcha) {
          clearInterval(interval);
          resolve();
          return;
        }

        try {
          const res = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => {
              const title = (document.title || '').toLowerCase();
              const isCf = title.includes('just a moment') ||
                           title.includes('attention required!') ||
                           document.querySelector('#challenge-form') !== null;
              const isCaptcha = document.querySelector('.g-recaptcha, .h-captcha') !== null;
              return isCf || isCaptcha;
            }
          });

          const stillHasCaptcha = res?.[0]?.result;
          if (!stillHasCaptcha) {
            clearInterval(interval);
            resolve();
          }
        } catch {
          // If execution fails, tab may have navigated to normal page
          clearInterval(interval);
          resolve();
        }
      }, 2500);

      this.captchaResolver = () => {
        clearInterval(interval);
        resolve();
      };
    });
  }

  resolveCaptchaManually() {
    this.isWaitingForCaptcha = false;
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
    while (this.isRunning) {
      if (this.isPaused) {
        await new Promise(r => setTimeout(r, 400));
        continue;
      }

      if (this.queue.length === 0) {
        if (this.activeWorkers === 0) break;
        await new Promise(r => setTimeout(r, 200));
        continue;
      }

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

      if (!this.visitedUrls.has(canonical) && !this.storage.knownUrlSet.has(canonical)) {
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
    this.totalDiscoveredInSession += added;
    if (this.onUrlFound) this.onUrlFound(processed);
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
    if (this.onProgress) {
      const elapsed = this.startTime ? (Date.now() - this.startTime) / 1000 : 0;
      const rps = elapsed > 0 ? (this.crawledCount / elapsed).toFixed(1) : 0;

      this.onProgress({
        crawled: this.crawledCount,
        queueLength: this.queue.length,
        activeWorkers: this.activeWorkers,
        totalDiscovered: this.totalDiscoveredInSession,
        duplicatesFiltered: this.duplicatesFiltered,
        subdomainsCount: this.subdomainsDiscovered.size,
        errors: this.errorCount,
        rps: rps
      });
    }
  }
}

// Global engine singleton
window.katanaEngine = new KatanaCrawlerEngine(window.katanaStorage);
