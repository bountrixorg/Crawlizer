/**
 * Katana Web Crawler - Background Service Worker
 * Handles extension lifecycle, context menu, and dashboard opening.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('Katana Web Crawler Extension installed successfully.');
});

// Listener for messages from popup or dashboard
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'open_dashboard') {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    sendResponse({ status: 'ok' });
  }
  return true;
});
