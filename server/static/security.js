'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const passkeys = window.CheckinPasskeys;
  const state = { csrf: '', authenticated: false, policy: {}, security: null, busy: false, uncertain: false, draft: false };

  function notice(message, error = false) {
    const target = state.authenticated ? $('security-message') : $('security-login-message');
    target.textContent = message;
    if (state.authenticated) { target.hidden = !message; target.className = `notice${error ? ' error' : ''}`; }
    else target.className = `inline-message${error ? ' error' : ''}`;
  }

  function renderLogin() {
    const policy = state.policy;
    const password = policy.password_login_allowed ?? (policy.auth_mode !== 'passkey' || policy.reauth_method === 'password');
    $('security-login').hidden = state.authenticated;
    $('security-workspace').hidden = !state.authenticated;
    $('security-logout').hidden = !state.authenticated;
    $('security-password-login').hidden = !password;
    $('security-login-password').required = password;
    $('security-login-password').disabled = !password || state.busy;
    $('security-login-button').disabled = !password || state.busy;
    $('security-passkey-login').hidden = !policy.passkey_available && policy.auth_mode !== 'passkey';
    $('security-passkey-login').disabled = state.busy || !policy.passkey_available || policy.passkey_origin_allowed === false || !passkeys.supported();
    $('security-login-hint').textContent = !password ? '当前入口仅允许 Passkey 登录. 请选择已绑定的设备或安全密钥.' : policy.auth_mode === 'passkey' ? '此处为本机恢复入口, 可以使用管理密码. 公网仍仅允许 Passkey.' : '使用管理密码或已绑定的 Passkey 登录.';
    if (policy.auth_mode === 'passkey' && !policy.passkey_available) $('security-login-hint').textContent += ' 没有匹配的可用密钥, 请通过 SSH 恢复.';
    else if (policy.passkey_available && !passkeys.supported()) $('security-login-hint').textContent += ' 当前浏览器或地址不支持 Passkey, 请使用支持 WebAuthn 的浏览器和 HTTPS 入口.';
  }

  function controls() {
    const info = state.security;
    const blocked = state.busy || state.uncertain || !info;
    $('security-register-form').inert = state.busy;
    $('security-current-password').disabled = state.busy;
    $('security-logout').disabled = state.busy;
    $('security-reload').disabled = state.busy;
    $('security-register').disabled = blocked || !info?.can_register || !passkeys.supported() || info.passkeys.length >= 10;
    $('verify-passkey').disabled = blocked || !info?.passkeys.length || info.passkey_origin_allowed === false || !passkeys.supported();
    $('enable-passkey-mode').disabled = blocked || info?.mode === 'passkey' || !info?.passkeys.some((key) => key.verified) || !info.passkey_available || info.passkey_origin_allowed === false || !passkeys.supported();
    $('enable-password-mode').disabled = blocked || info?.mode !== 'passkey';
    document.querySelectorAll('[data-delete-passkey]').forEach((button) => {
      const key = info?.passkeys.find((entry) => entry.id === button.dataset.deletePasskey);
      const last = info?.mode === 'passkey' && key?.verified && info.passkeys.filter((entry) => entry.verified).length <= 1;
      button.disabled = blocked || last;
      button.title = last ? 'Passkey 版必须保留至少一把当前入口已验证的密钥' : '删除此 Passkey 前需要重新验证身份';
    });
    renderLogin();
  }

  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
    const headers = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (options.method && options.method !== 'GET' && path !== '/api/login' && !path.startsWith('/api/passkey/login/')) headers['X-CSRF-Token'] = state.csrf;
    const response = await fetch(path, { method: options.method || 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal, headers, ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}) });
    let result;
    try { result = await response.json(); }
    catch (_) { const error = new Error('服务响应无法确认, 请重新读取安全状态.'); error.status = 0; throw error; }
    if (!response.ok) {
      if (response.status === 401 && path !== '/api/login' && !path.startsWith('/api/passkey/login/')) {
        state.authenticated = false; state.csrf = ''; renderLogin();
      }
      const error = new Error(result.error || '安全操作未完成'); error.status = response.status; throw error;
    }
    if (result.csrf) state.csrf = result.csrf;
    if (result.authenticated === true) state.authenticated = true;
    return result;
    } catch (error) {
      if (error.name === 'AbortError' || error instanceof TypeError) {
        const unavailable = new Error(error.name === 'AbortError' ? '请求超时, 请重新读取安全状态.' : '网络连接失败, 请重新读取安全状态.');
        unavailable.status = 0;
        throw unavailable;
      }
      throw error;
    } finally { clearTimeout(timeout); }
  }

  function time(value) {
    return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '暂无';
  }

  function render() {
    const info = state.security;
    $('security-mode-badge').textContent = info.mode === 'passkey' ? 'Passkey 版' : '密码版';
    $('security-mode-description').textContent = info.mode === 'passkey' ? '公网密码入口已关闭. 登录和敏感操作使用 Passkey, SSH 恢复入口保留.' : '管理密码登录已启用. 可先添加和验证 Passkey, 再切换登录模式.';
    $('security-mode-hint').textContent = info.mode === 'passkey' ? '切换回密码版会重新开启公网密码登录, 需要先验证当前身份.' : info.passkeys.some((key) => key.verified) ? '已有验证成功的密钥. 启用前仍会重新验证 Passkey, 避免失去登录入口.' : '请先添加密钥并点击验证 Passkey, 验证成功后才能启用 Passkey 版.';
    $('security-origin-hint').textContent = info.passkey_origin_allowed === false ? '当前地址不适合注册或验证此站点的 Passkey. 请使用配置的 HTTPS 管理入口; 地址已变更时可通过 SSH 恢复.' : '这些密钥用于当前管理入口. 换用其他域名时, 原密钥可能无法使用.';
    $('security-key-count').textContent = `${info.passkeys.length} / 10`;
    $('security-password-reauth').hidden = info.reauth_method === 'passkey';
    $('security-register-hint').textContent = !passkeys.supported() ? '浏览器或当前地址不支持 Passkey. 请使用支持 WebAuthn 的浏览器和 HTTPS.' : !info.can_register ? '请在允许注册的 HTTPS 管理入口操作.' : info.passkeys.length >= 10 ? '已达到 10 把密钥的上限, 请先删除不再使用的密钥.' : info.reauth_method === 'passkey' ? '添加前会使用已有 Passkey 验证身份, 然后创建新密钥.' : '先在下方输入当前管理密码, 再点击添加 Passkey.';
    const root = $('security-keys'); root.replaceChildren();
    for (const key of info.passkeys) {
      const card = document.createElement('article'); card.className = 'security-key';
      const title = document.createElement('h3'); title.textContent = key.label || '未命名 Passkey';
      const status = document.createElement('span'); status.className = `badge ${key.verified ? 'success' : 'warning'}`; status.textContent = key.verified ? '已验证' : '待验证';
      const meta = document.createElement('p'); meta.className = 'muted small'; meta.textContent = `添加: ${time(key.created_at)}. 最近使用: ${time(key.last_used_at)}.`;
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button danger-soft'; remove.textContent = '删除'; remove.dataset.deletePasskey = key.id; remove.setAttribute('aria-label', '删除 Passkey ' + (key.label || '未命名密钥'));
      remove.addEventListener('click', () => deleteKey(key));
      const heading = document.createElement('div'); heading.className = 'security-key-heading'; heading.append(title, status, remove);
      card.append(heading, meta); root.append(card);
    }
    if (!info.passkeys.length) { const empty = document.createElement('p'); empty.className = 'muted small'; empty.textContent = '尚未绑定 Passkey. 当前密码登录会保留, 添加和验证成功后才可切换.'; root.append(empty); }
    controls();
  }

  async function load() {
    const result = await api('/api/security');
    if (!Array.isArray(result.passkeys)) throw new Error('安全状态格式无效, 请重新读取.');
    state.security = result; state.uncertain = false;
    state.policy = { ...state.policy, auth_mode: result.mode, reauth_method: result.reauth_method, password_login_allowed: result.password_login_allowed ?? (result.mode !== 'passkey' || result.reauth_method === 'password'), passkey_available: result.passkey_available, passkey_origin_allowed: result.passkey_origin_allowed };
    render();
  }

  async function confirmIdentity(forcePasskey = false) {
    if (forcePasskey || state.security.reauth_method === 'passkey') return passkeys.reauth(api);
    const password = $('security-current-password').value;
    if (!password) throw new Error('请先在确认当前身份中输入当前管理密码.');
    try { return (await api('/api/security/reauth', { method: 'POST', body: { password } })).reauth_token; }
    finally { $('security-current-password').value = ''; }
  }

  async function perform(action, mutating = false) {
    if (state.busy || (mutating && state.uncertain)) return;
    state.busy = true; controls();
    try { await action(); }
    catch (error) {
      if (mutating && !['NotAllowedError', 'AbortError', 'InvalidStateError', 'SecurityError', 'NotSupportedError'].includes(error.name) && (!error.status || error.status >= 500) && !error.message.startsWith('请先')) {
        state.uncertain = true; notice('操作结果尚未确认. 请先重新读取密钥和登录模式, 避免重复提交.', true);
      } else notice(passkeys.errorMessage(error), true);
      if (!state.authenticated) {
        try { state.policy = await api('/api/session'); renderLogin(); }
        catch (_) { /* The visible login error remains available while offline. */ }
      }
    } finally { state.busy = false; controls(); }
  }

  async function enter(session) {
    state.policy = session; state.authenticated = true; state.csrf = session.csrf;
    $('security-login-password').value = ''; renderLogin(); await load();
  }

  $('security-login-form').addEventListener('submit', (event) => {
    event.preventDefault(); if ($('security-login-button').disabled) return;
    perform(async () => enter(await api('/api/login', { method: 'POST', body: { password: $('security-login-password').value } })));
  });
  $('security-passkey-login').addEventListener('click', () => perform(async () => enter(await passkeys.login(api))));
  $('security-reload').addEventListener('click', () => perform(async () => { await load(); notice('已重新读取当前密钥和登录模式.'); }));
  $('security-key-label').addEventListener('input', () => { state.draft = !!$('security-key-label').value; });
  $('security-register-form').addEventListener('submit', (event) => {
    event.preventDefault(); if ($('security-register').disabled) return;
    perform(async () => {
      const label = $('security-key-label').value.trim(); if (!label) throw new Error('请先填写密钥名称.');
      const token = await confirmIdentity();
      await passkeys.register(api, label, token);
      $('security-key-label').value = ''; state.draft = false;
      await load(); notice('Passkey 已添加. 请点击验证 Passkey, 成功后再启用 Passkey 版.');
    }, true);
  });
  $('verify-passkey').addEventListener('click', () => perform(async () => {
    await passkeys.reauth(api); await load(); notice('Passkey 验证成功. 你可以选择启用 Passkey 版.');
  }));
  async function switchMode(mode) {
    if (mode === 'password' && !window.confirm('切换为密码版会重新开启公网管理密码登录. 是否继续?')) return;
    perform(async () => {
      const token = await confirmIdentity(mode === 'passkey');
      await api('/api/security/mode', { method: 'POST', body: { mode, revision: state.security.revision, reauth_token: token } });
      await load(); notice(mode === 'passkey' ? '已启用 Passkey 版. 公网密码登录已关闭, 原会话已更新.' : '已切换为密码版. 公网管理密码登录已开启.');
    }, true);
  }
  $('enable-passkey-mode').addEventListener('click', () => switchMode('passkey'));
  $('enable-password-mode').addEventListener('click', () => switchMode('password'));
  async function deleteKey(key) {
    if (!window.confirm('删除后此 Passkey 将不能用于登录. 是否删除 ' + (key.label || '此密钥') + '?')) return;
    perform(async () => {
      const token = await confirmIdentity();
      await api('/api/security/passkeys/' + encodeURIComponent(key.id), { method: 'DELETE', body: { revision: state.security.revision, reauth_token: token } });
      await load(); notice('Passkey 已删除, 请核对剩余密钥.');
    }, true);
  }
  $('security-logout').addEventListener('click', () => {
    if (state.draft && !window.confirm('退出会丢弃未保存的密钥名称. 是否继续?')) return;
    perform(async () => {
      await api('/api/logout', { method: 'POST', body: {} }); state.authenticated = false; state.csrf = ''; state.security = null;
      $('security-current-password').value = ''; $('security-key-label').value = ''; state.draft = false;
      state.policy = await api('/api/session'); renderLogin(); notice('');
    });
  });
  window.addEventListener('beforeunload', (event) => { if (state.draft) { event.preventDefault(); event.returnValue = ''; } });
  perform(async () => {
    const session = await api('/api/session'); state.policy = session; state.authenticated = !!session.authenticated; state.csrf = session.csrf || '';
    renderLogin(); if (state.authenticated) await load(); else notice('');
  });
})();
