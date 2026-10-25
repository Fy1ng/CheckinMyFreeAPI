// Defense in depth for the trusted loopback page. This is a renderer guard,
// not a replacement for a native navigation policy in the webview engine.
(origin => {
  if (location.origin !== origin || window.__checkinDesktopGuard) return;
  Object.defineProperty(window, '__checkinDesktopGuard', { value: true });
  const pages = new Set(['/', '/status', '/backups', '/security']);
  function allowed(value, download = false) {
    try {
      const url = new URL(value, location.href);
      const page = pages.has(url.pathname);
      const backup = download && /^\/api\/backups\/[a-zA-Z0-9._-]+$/.test(url.pathname) && !url.search && !url.hash;
      return url.origin === origin && (page || backup) && !url.username && !url.password;
    } catch (_) { return false; }
  }
  function blocked(value) {
    let box = document.getElementById('checkin-desktop-link-notice');
    if (!box) {
      box = document.createElement('aside'); box.id = 'checkin-desktop-link-notice'; box.setAttribute('role', 'alert');
      Object.assign(box.style, { position: 'fixed', left: '16px', right: '16px', bottom: '16px', maxWidth: '620px', padding: '16px', border: '1px solid #c8dcd4', borderRadius: '10px', background: '#f4faf7', color: '#153e35', boxShadow: '0 8px 24px #0002', zIndex: '2147483000', font: '14px/1.5 sans-serif' });
      document.body.append(box);
    }
    box.replaceChildren();
    const text = document.createElement('p'); text.textContent = '外部链接已阻止. 请复制链接到系统浏览器打开.'; text.style.margin = '0 0 10px';
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = '复制链接';
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(String(value)); text.textContent = '链接已复制. 请在系统浏览器中打开.'; }
      catch (_) { text.textContent = '浏览器未允许复制. 请通过托盘菜单打开系统浏览器, 再查阅此链接.'; }
    });
    const close = document.createElement('button'); close.type = 'button'; close.textContent = '关闭'; close.style.marginLeft = '10px'; close.addEventListener('click', () => box.remove());
    box.append(text, copy, close);
  }
  if (window.navigation) navigation.addEventListener('navigate', event => {
    if (!allowed(event.destination.url, event.downloadRequest !== null) && event.cancelable) { event.preventDefault(); blocked(event.destination.url); }
  });
  document.addEventListener('click', event => {
    const anchor = event.target.closest?.('a[href], area[href]');
    if (anchor && !allowed(anchor.href, anchor.hasAttribute('download'))) { event.preventDefault(); event.stopImmediatePropagation(); blocked(anchor.href); }
  }, true);
  document.addEventListener('submit', event => {
    const form = event.target;
    if (form instanceof HTMLFormElement && !allowed(form.action)) { event.preventDefault(); event.stopImmediatePropagation(); blocked(form.action); }
  }, true);
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    if (allowed(this.action)) return originalSubmit.call(this);
    blocked(this.action);
  };
  window.open = function (value) {
    if (allowed(value)) { location.assign(new URL(value, location.href).href); return window; }
    blocked(value); return null;
  };
})(__CHECKIN_DESKTOP_ORIGIN__);
