/**
 * Crawlizer Multi-Theme Customization Manager (v1.2.0)
 * Supports 8 Curated Hacker/Modern Themes + Auto (OS Scheme Follower)
 * Complete Palette Transformation & Rock-Solid Persistence
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CrawlizerTheme = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const STORAGE_KEY = 'crawlizer_theme';

  // Master Themes Array — Extensible Registry
  const THEMES = [
    // Dark Themes
    {
      id: 'matrix',
      name: 'Matrix',
      label: 'Matrix (Cyberpunk)',
      type: 'dark',
      dots: ['#0a0e14', '#00f0ff', '#ff2bd6'],
      primary: '#00f0ff'
    },
    {
      id: 'midnight',
      name: 'Midnight Blue',
      label: 'Midnight Blue',
      type: 'dark',
      dots: ['#070c18', '#38bdf8', '#a855f7'],
      primary: '#38bdf8'
    },
    {
      id: 'dracula',
      name: 'Dracula',
      label: 'Dracula',
      type: 'dark',
      dots: ['#21222c', '#bd93f9', '#ff79c6'],
      primary: '#bd93f9'
    },
    {
      id: 'crimson',
      name: 'Crimson Ops',
      label: 'Crimson Ops',
      type: 'dark',
      dots: ['#0b0607', '#ff2a4b', '#ff6b35'],
      primary: '#ff2a4b'
    },
    {
      id: 'nord',
      name: 'Nord Frost',
      label: 'Nord Frost',
      type: 'dark',
      dots: ['#242933', '#88c0d0', '#81a1c1'],
      primary: '#88c0d0'
    },
    // Light Themes
    {
      id: 'clean-light',
      name: 'Clean Light',
      label: 'Clean Light',
      type: 'light',
      dots: ['#f8fafc', '#4f46e5', '#0284c7'],
      primary: '#4f46e5'
    },
    {
      id: 'paper-mint',
      name: 'Paper Mint',
      label: 'Paper Mint',
      type: 'light',
      dots: ['#f4f7f5', '#0d9488', '#059669'],
      primary: '#0d9488'
    },
    {
      id: 'solar-sand',
      name: 'Solar Sand',
      label: 'Solar Sand',
      type: 'light',
      dots: ['#fbf8f2', '#d97706', '#ea580c'],
      primary: '#d97706'
    },
    // Auto Option
    {
      id: 'auto',
      name: 'Auto (System)',
      label: 'Auto (Follow OS)',
      type: 'system',
      dots: ['#0a0e14', '#ffffff', '#38bdf8'],
      primary: '#38bdf8'
    }
  ];

  function getStoredTheme() {
    try {
      const val = localStorage.getItem(STORAGE_KEY);
      if (val) return val;
    } catch (e) {}
    return 'matrix';
  }

  function resolveThemeId(themeId) {
    if (themeId === 'auto') {
      const isLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      return isLight ? 'clean-light' : 'matrix';
    }
    const found = THEMES.find(t => t.id === themeId);
    return found ? themeId : 'matrix';
  }

  function applyTheme(themeId, withTransition = true) {
    const rawThemeId = themeId || getStoredTheme();
    const resolved = resolveThemeId(rawThemeId);
    const doc = document.documentElement;
    const body = document.body;

    if (withTransition) {
      doc.setAttribute('data-theme-transitioning', 'true');
    }

    doc.setAttribute('data-theme', resolved);
    doc.setAttribute('data-theme-setting', rawThemeId);
    if (body) {
      body.setAttribute('data-theme', resolved);
      body.setAttribute('data-theme-setting', rawThemeId);
    }

    try {
      localStorage.setItem(STORAGE_KEY, rawThemeId);
    } catch (e) {}

    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ [STORAGE_KEY]: rawThemeId });
      }
    } catch (e) {}

    // Update active state in any theme dropdowns
    updateAllDropdownUI(rawThemeId);

    if (withTransition) {
      setTimeout(() => {
        doc.removeAttribute('data-theme-transitioning');
      }, 220);
    }

    // Broadcast theme change event so charts, canvas, and svg sparklines immediately update
    try {
      window.dispatchEvent(new CustomEvent('crawlizer:themechange', {
        detail: {
          themeId: rawThemeId,
          resolvedTheme: resolved,
          themeConfig: THEMES.find(t => t.id === rawThemeId) || THEMES[0]
        }
      }));
    } catch (e) {}

    return resolved;
  }

  function cycleTheme() {
    const current = getStoredTheme();
    const idx = THEMES.findIndex(t => t.id === current);
    const nextIdx = (idx + 1) % THEMES.length;
    const nextTheme = THEMES[nextIdx];
    applyTheme(nextTheme.id, true);
    return nextTheme;
  }

  // Active instances of dropdown controllers
  const dropdownInstances = [];

  function updateAllDropdownUI(activeThemeId) {
    dropdownInstances.forEach(inst => {
      inst.updateActive(activeThemeId);
    });
  }

  /**
   * Initializes a Theme Switcher dropdown menu
   */
  function initThemeDropdown(options = {}) {
    const wrap = typeof options.wrap === 'string' ? document.getElementById(options.wrap) : options.wrap;
    const button = typeof options.button === 'string' ? document.getElementById(options.button) : options.button;
    const popover = typeof options.popover === 'string' ? document.getElementById(options.popover) : options.popover;
    const labelEl = typeof options.label === 'string' ? document.getElementById(options.label) : options.label;
    const swatchEl = typeof options.swatch === 'string' ? document.getElementById(options.swatch) : options.swatch;

    if (!button || !popover) return null;

    // Render popover options
    function renderPopoverContent() {
      popover.innerHTML = '';

      const groups = [
        { title: 'Dark Themes', filter: t => t.type === 'dark' },
        { title: 'Light Themes', filter: t => t.type === 'light' },
        { title: 'System', filter: t => t.type === 'system' }
      ];

      groups.forEach(group => {
        const items = THEMES.filter(group.filter);
        if (items.length === 0) return;

        const header = document.createElement('div');
        header.className = 'theme-group-header';
        header.textContent = group.title;
        popover.appendChild(header);

        items.forEach(t => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'theme-option-btn';
          btn.dataset.themeId = t.id;
          btn.setAttribute('role', 'menuitem');

          btn.innerHTML = `
            <span class="theme-option-left">
              <span class="theme-trigger-swatch">
                <span class="swatch-dot" style="background: ${t.dots[0]};"></span>
                <span class="swatch-dot" style="background: ${t.dots[1]};"></span>
                <span class="swatch-dot" style="background: ${t.dots[2]};"></span>
              </span>
              <span>${t.name}</span>
            </span>
            <span class="theme-check-icon">✓</span>
          `;

          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            applyTheme(t.id, true);
            close();
            button.focus();
            if (options.onSelect) options.onSelect(t);
          });

          popover.appendChild(btn);
        });
      });
    }

    function updateActive(activeThemeId) {
      const currentId = activeThemeId || getStoredTheme();
      const currentTheme = THEMES.find(t => t.id === currentId) || THEMES[0];

      if (labelEl) {
        labelEl.textContent = currentTheme.name;
      }

      if (swatchEl) {
        swatchEl.innerHTML = `
          <span class="swatch-dot" style="background: ${currentTheme.dots[0]};"></span>
          <span class="swatch-dot" style="background: ${currentTheme.dots[1]};"></span>
          <span class="swatch-dot" style="background: ${currentTheme.dots[2]};"></span>
        `;
      }

      const allBtns = popover.querySelectorAll('.theme-option-btn');
      allBtns.forEach(btn => {
        if (btn.dataset.themeId === currentId) {
          btn.classList.add('active');
          btn.setAttribute('aria-selected', 'true');
        } else {
          btn.classList.remove('active');
          btn.setAttribute('aria-selected', 'false');
        }
      });
    }

    function open() {
      popover.classList.add('open');
      button.setAttribute('aria-expanded', 'true');
      const activeBtn = popover.querySelector('.theme-option-btn.active');
      if (activeBtn) activeBtn.focus();
    }

    function close() {
      popover.classList.remove('open');
      button.setAttribute('aria-expanded', 'false');
    }

    function toggle() {
      if (popover.classList.contains('open')) {
        close();
      } else {
        open();
      }
    }

    button.addEventListener('click', (e) => {
      e.stopPropagation();
      toggle();
    });

    // Keyboard navigation within popover
    popover.addEventListener('keydown', (e) => {
      const btns = Array.from(popover.querySelectorAll('.theme-option-btn'));
      const activeIdx = btns.indexOf(document.activeElement);

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const next = (activeIdx + 1) % btns.length;
        btns[next].focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        const prev = (activeIdx - 1 + btns.length) % btns.length;
        btns[prev].focus();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        close();
        button.focus();
      }
    });

    // Close when clicking outside
    document.addEventListener('click', (e) => {
      if (!wrap || !wrap.contains(e.target)) {
        close();
      }
    });

    renderPopoverContent();
    updateActive(getStoredTheme());

    const instance = { updateActive, open, close, toggle };
    dropdownInstances.push(instance);
    return instance;
  }

  // Global Listeners: Alt+T Shortcut & OS Scheme Change
  if (typeof window !== 'undefined') {
    window.addEventListener('keydown', (e) => {
      if (e.altKey && (e.key === 't' || e.key === 'T')) {
        e.preventDefault();
        cycleTheme();
      }
    });

    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
        if (getStoredTheme() === 'auto') {
          applyTheme('auto', true);
        }
      });
    }

    // Attempt sync with extension chrome.storage if running in extension context
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      try {
        chrome.storage.local.get([STORAGE_KEY], (res) => {
          if (res && res[STORAGE_KEY]) {
            const current = getStoredTheme();
            if (current !== res[STORAGE_KEY]) {
              applyTheme(res[STORAGE_KEY], false);
            }
          }
        });
      } catch (e) {}
    }
  }

  // Immediately apply stored theme on script load
  try {
    const initTheme = getStoredTheme();
    applyTheme(initTheme, false);
    if (typeof document !== 'undefined') {
      document.addEventListener('DOMContentLoaded', () => {
        applyTheme(getStoredTheme(), false);
      });
    }
  } catch (e) {}

  return {
    THEMES,
    getStoredTheme,
    resolveThemeId,
    applyTheme,
    cycleTheme,
    initThemeDropdown
  };
});
