/**
 * Crawlizer - Lightweight Content Script Helper
 * Passive DOM reader without active separate crawling loops or background queues.
 */

// Passive listener for page data requests
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageData') {
      try {
        const scripts = [];
        document.querySelectorAll('script').forEach(el => {
          scripts.push({
            src: el.src || el.getAttribute('src') || '',
            content: el.textContent || '',
            type: (el.getAttribute('type') || '').toLowerCase()
          });
        });

        sendResponse({
          url: window.location.href,
          html: document.documentElement ? document.documentElement.outerHTML.slice(0, 2000000) : '',
          scripts
        });
      } catch (err) {
        sendResponse({ error: err.message, url: window.location.href, scripts: [] });
      }
      return true;
    }

    if (request.action === 'getScanStatus') {
      sendResponse({ scanning: false, complete: true, packages: [] });
      return true;
    }

    return false;
  });
}
