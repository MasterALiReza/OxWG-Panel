/**
 * OxSelect - Unified Global Custom Dropdown System
 * Replaces crude native browser/OS select menus with sleek, theme-adaptive,
 * accessible custom dropdowns with zero disruption to underlying select logic.
 *
 * Single Source of Truth for all dropdowns across OxWg Panel.
 */
(function (global) {
  'use strict';

  const instances = new WeakMap();

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatLabel(text) {
    if (!text) return '';
    const clean = String(text).trim();
    if (clean.includes('★')) {
      const base = clean.replace(/★/g, '').trim();
      return `${escapeHtml(base)} <i class="fas fa-star ox-select-star" title="Active profile" aria-hidden="true"></i>`;
    }
    return escapeHtml(clean);
  }

  function isEligibleSelect(el) {
    if (!el || el.tagName !== 'SELECT') return false;
    if (el.dataset.noCustom === 'true' || el.classList.contains('no-ox-select')) return false;
    if (el.classList.contains('peer-scope-native') || el.classList.contains('studio8-hidden')) return false;
    if (el.hidden || el.style.display === 'none') {
      // If hidden native select, skip unless it's inside an already established shell
      if (!el.closest('.ox-select-shell')) return false;
    }
    return true;
  }

  class CustomSelect {
    constructor(select, config = {}) {
      if (!select || instances.has(select)) return instances.get(select);
      this.select = select;
      this.config = Object.assign({
        customClass: '',
        placeholder: 'Select…',
      }, config);

      this.isOpen = false;
      this.focusedIndex = -1;

      this.buildDOM();
      this.bindEvents();
      this.observeChanges();

      instances.set(select, this);
    }

    buildDOM() {
      // Create or locate shell wrapper
      let shell = this.select.parentElement;
      if (!shell || !shell.classList.contains('ox-select-shell')) {
        shell = document.createElement('div');
        shell.className = 'ox-select-shell';
        this.select.parentNode.insertBefore(shell, this.select);
        shell.appendChild(this.select);
      }
      this.shell = shell;

      // Copy relevant classes and styles from native select
      if (this.select.classList.contains('sm') || this.select.classList.contains('peerx-sm')) {
        shell.classList.add('sm');
      }
      if (this.select.classList.contains('input') || this.select.classList.contains('sel')) {
        shell.classList.add('ox-input-variant');
      }
      if (this.config.customClass) {
        shell.classList.add(this.config.customClass);
      }
      if (this.select.id) {
        shell.dataset.for = this.select.id;
        if (this.select.id === 'ep-saved') {
          shell.classList.add('ox-ep-saved-shell');
        }
      }

      // Preserve width if explicitly set in inline style
      if (this.select.style.width) {
        shell.style.width = this.select.style.width;
      }

      // Trigger button
      let trigger = shell.querySelector(':scope > .ox-select-trigger');
      if (!trigger) {
        trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'ox-select-trigger';
        trigger.setAttribute('aria-haspopup', 'listbox');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.innerHTML = `
          <span class="ox-select-label"></span>
          <span class="ox-select-chevron"><i class="fas fa-chevron-down" aria-hidden="true"></i></span>
        `;
        shell.insertBefore(trigger, this.select);
      }
      this.trigger = trigger;
      this.labelEl = trigger.querySelector('.ox-select-label');

      // Dropdown menu
      let menu = shell.querySelector(':scope > .ox-select-menu');
      if (!menu) {
        menu = document.createElement('div');
        menu.className = 'ox-select-menu';
        menu.setAttribute('role', 'listbox');
        menu.hidden = true;
        shell.appendChild(menu);
      }
      this.menu = menu;

      this.renderOptions();
      this.syncTrigger();
      this.syncDisabled();
    }

    renderOptions() {
      const options = Array.from(this.select.options);
      if (!options.length) {
        this.menu.innerHTML = '<div class="ox-select-item" style="opacity:0.6; cursor:default;">No options available</div>';
        return;
      }

      this.menu.innerHTML = options.map((opt, idx) => {
        const isSelected = opt.selected || opt.value === this.select.value;
        const isDisabled = opt.disabled;
        const val = escapeHtml(opt.value);
        const formatted = formatLabel(opt.textContent || opt.value);
        return `
          <button type="button" class="ox-select-item${isSelected ? ' selected' : ''}${isDisabled ? ' disabled' : ''}" data-value="${val}" data-index="${idx}" role="option" aria-selected="${isSelected ? 'true' : 'false'}" ${isDisabled ? 'disabled' : ''}>
            <span class="ox-select-item-text">${formatted}</span>
            <span class="ox-select-check"><i class="fas fa-check" aria-hidden="true"></i></span>
          </button>
        `;
      }).join('');
    }

    syncTrigger() {
      const selected = this.select.options[this.select.selectedIndex];
      if (selected && (selected.textContent || selected.value)) {
        this.labelEl.innerHTML = formatLabel(selected.textContent || selected.value);
      } else if (this.select.options.length > 0 && this.select.options[0]) {
        this.labelEl.innerHTML = formatLabel(this.select.options[0].textContent || this.select.options[0].value);
      } else {
        this.labelEl.innerHTML = escapeHtml(this.config.placeholder);
      }

      // Sync selected class in menu
      const items = this.menu.querySelectorAll('.ox-select-item');
      items.forEach((item, idx) => {
        const isSel = idx === this.select.selectedIndex;
        item.classList.toggle('selected', isSel);
        item.setAttribute('aria-selected', isSel ? 'true' : 'false');
      });
    }

    syncDisabled() {
      const disabled = this.select.disabled;
      this.trigger.disabled = disabled;
      this.trigger.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      this.shell.classList.toggle('disabled', disabled);
    }

    open() {
      if (this.isOpen || this.select.disabled) return;
      // Close any other open dropdowns first
      document.querySelectorAll('.ox-select-menu.open').forEach(m => {
        m.classList.remove('open');
        m.hidden = true;
        const trg = m.parentElement?.querySelector('.ox-select-trigger');
        if (trg) trg.setAttribute('aria-expanded', 'false');
      });

      // Close profile action menu if open
      const pm = document.getElementById('profile-menu');
      if (pm) pm.style.display = 'none';

      // Check vertical positioning to avoid clipping
      const rect = this.trigger.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      const spaceAbove = rect.top;
      if (spaceBelow < 220 && spaceAbove > spaceBelow) {
        this.shell.classList.add('ox-dropup');
      } else {
        this.shell.classList.remove('ox-dropup');
      }

      // Check horizontal positioning to avoid right-edge overflow
      const spaceRight = window.innerWidth - rect.right;
      if (spaceRight < 160 || this.shell.closest('.subx-page-controls, .peerx-page-controls, .np-page-controls')) {
        this.shell.classList.add('ox-drop-right-align');
      } else {
        this.shell.classList.remove('ox-drop-right-align');
      }

      this.isOpen = true;
      this.menu.hidden = false;
      // Force reflow for smooth animation
      this.menu.offsetHeight;
      this.menu.classList.add('open');
      this.trigger.setAttribute('aria-expanded', 'true');

      // Scroll selected item into view
      const selectedItem = this.menu.querySelector('.ox-select-item.selected');
      if (selectedItem) {
        selectedItem.scrollIntoView({ block: 'nearest' });
      }
    }

    close(restoreFocus = false) {
      if (!this.isOpen) return;
      this.isOpen = false;
      this.menu.classList.remove('open');
      this.trigger.setAttribute('aria-expanded', 'false');
      setTimeout(() => {
        if (!this.isOpen) this.menu.hidden = true;
      }, 160);
      if (restoreFocus) this.trigger.focus();
    }

    toggle() {
      if (this.isOpen) this.close();
      else this.open();
    }

    bindEvents() {
      this.trigger.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.toggle();
      });

      this.menu.addEventListener('click', (e) => {
        const item = e.target.closest('.ox-select-item');
        if (!item || item.disabled) return;
        e.preventDefault();
        e.stopPropagation();

        const val = item.dataset.value;
        const idx = parseInt(item.dataset.index, 10);

        if (!isNaN(idx) && this.select.selectedIndex !== idx) {
          this.select.selectedIndex = idx;
          this.select.value = val;
          this.select.dispatchEvent(new Event('input', { bubbles: true }));
          this.select.dispatchEvent(new Event('change', { bubbles: true }));
        }

        this.syncTrigger();
        this.close(true);
      });

      // Listen for external change and input events on native select
      this.select.addEventListener('change', () => {
        this.syncTrigger();
        this.syncDisabled();
      });
      this.select.addEventListener('input', () => {
        this.syncTrigger();
      });

      // Keyboard navigation
      this.trigger.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.open();
        }
      });

      this.menu.addEventListener('keydown', (e) => {
        const items = Array.from(this.menu.querySelectorAll('.ox-select-item:not([disabled])'));
        if (!items.length) return;

        if (e.key === 'Escape') {
          e.preventDefault();
          this.close(true);
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          this.focusedIndex = (this.focusedIndex + 1) % items.length;
          items[this.focusedIndex]?.focus();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          this.focusedIndex = (this.focusedIndex - 1 + items.length) % items.length;
          items[this.focusedIndex]?.focus();
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const activeEl = document.activeElement;
          if (activeEl && activeEl.classList.contains('ox-select-item')) {
            activeEl.click();
          }
        }
      });

      // Document click outside
      document.addEventListener('click', (e) => {
        if (this.isOpen && !this.shell.contains(e.target)) {
          this.close();
        }
      });
    }

    observeChanges() {
      // Re-render options when native select innerHTML, children, or attributes change
      this.observer = new MutationObserver(() => {
        this.renderOptions();
        this.syncTrigger();
        this.syncDisabled();
      });
      this.observer.observe(this.select, {
        childList: true,
        subtree: true,
        characterData: true,
        attributes: true,
        attributeFilter: ['disabled', 'hidden']
      });
    }

    refresh() {
      this.renderOptions();
      this.syncTrigger();
      this.syncDisabled();
    }

    destroy() {
      if (this.observer) this.observer.disconnect();
      instances.delete(this.select);
      if (this.shell && this.shell.parentNode) {
        this.shell.parentNode.insertBefore(this.select, this.shell);
        this.shell.remove();
      }
    }
  }

  let autoInitDebounce = null;

  const OxSelect = {
    enhance(select, config) {
      if (!isEligibleSelect(select)) return null;
      return new CustomSelect(select, config);
    },
    refresh(select) {
      if (!select) return;
      const instance = instances.get(select);
      if (instance) instance.refresh();
      else if (isEligibleSelect(select)) new CustomSelect(select);
    },
    destroy(select) {
      const instance = instances.get(select);
      if (instance) instance.destroy();
    },
    initAll(root = document) {
      if (!root || !root.querySelectorAll) return;
      root.querySelectorAll('select').forEach((sel) => {
        if (isEligibleSelect(sel) && !instances.has(sel)) {
          new CustomSelect(sel);
        }
      });
    }
  };

  global.OxSelect = OxSelect;

  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => OxSelect.initAll());
  } else {
    OxSelect.initAll();
  }

  // Global MutationObserver to automatically enhance dynamically created selects (like modals, AJAX lists, etc.)
  if (typeof MutationObserver !== 'undefined') {
    const globalObserver = new MutationObserver((mutations) => {
      let shouldInit = false;
      for (const m of mutations) {
        if (m.type === 'childList' && m.addedNodes.length > 0) {
          for (const node of m.addedNodes) {
            if (node.nodeType === 1) { // ELEMENT_NODE
              if (node.tagName === 'SELECT' || (node.querySelector && node.querySelector('select'))) {
                shouldInit = true;
                break;
              }
            }
          }
        }
        if (shouldInit) break;
      }
      if (shouldInit) {
        clearTimeout(autoInitDebounce);
        autoInitDebounce = setTimeout(() => {
          OxSelect.initAll(document.body);
        }, 15);
      }
    });

    if (document.body) {
      globalObserver.observe(document.body, { childList: true, subtree: true });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        globalObserver.observe(document.body, { childList: true, subtree: true });
      });
    }
  }

})(typeof window !== 'undefined' ? window : this);
