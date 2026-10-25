'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { csrf: '', config: null, revision: null, busy: false, dirty: false, ticket: null, uncertain: false, reauthMethod: 'password' };
  function loginPolicy(policy) {
    const password = policy.password_login_allowed ?? (policy.auth_mode !== 'passkey' || policy.reauth_method === 'password');
    state.reauthMethod = policy.reauth_method || (policy.auth_mode === 'passkey' ? 'passkey' : 'password');
    $('backup-password-login').hidden = !password;
    $('backup-login-password').required = password;
    $('backup-passkey-login').hidden = !policy.passkey_available;
    $('backup-passkey-login').disabled = !window.CheckinPasskeys?.supported();
    $('restore-password-reauth').hidden = state.reauthMethod === 'passkey';
    $('restore-admin-password').required = state.reauthMethod !== 'passkey';
    $('restore-passkey-reauth').hidden = state.reauthMethod !== 'passkey';
    if (!password && !policy.passkey_available) message('此入口没有可用的 Passkey. 请通过 SSH 恢复管理入口.', true);
    else if (!password && !window.CheckinPasskeys?.supported()) message('当前浏览器不支持 Passkey, 请使用支持 WebAuthn 的浏览器.', true);
  }
  function message(text, error = false) {
    $('backup-message').textContent = text;
    $('backup-message').className = `notice${error ? ' error' : ''}`;
    $('backup-message').hidden = !text;
    if (!$('backup-login').hidden) {
      $('backup-login-message').textContent = text;
      $('backup-login-message').className = `inline-message${error ? ' error' : ''}`;
    }
  }
  function controls() {
    for (const id of ['backup-settings-form', 'backup-preview-form', 'backup-restore-form']) $(id).inert = state.busy;
    $('backup-create').disabled = state.busy || state.dirty || state.uncertain || !state.config?.backups?.password;
    $('backup-save').disabled = state.busy || !state.dirty || state.uncertain;
    $('backup-reload').disabled = state.busy;
    $('backup-refresh-list').disabled = state.busy;
    $('backup-preview').disabled = state.busy || state.dirty || state.uncertain;
    $('backup-restore').disabled = state.busy || state.dirty || state.uncertain || !state.ticket;
  }
  async function api(path, options = {}) {
    const headers = { Accept: 'application/json', ...(options.headers || {}) };
    const form = options.body instanceof FormData;
    if (options.body !== undefined && !form) headers['Content-Type'] = 'application/json';
    if (options.method && options.method !== 'GET' && path !== '/api/login') headers['X-CSRF-Token'] = state.csrf;
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error', body: options.body === undefined || form ? options.body : JSON.stringify(options.body) });
    if (response.status === 401) {
      state.config = null; state.ticket = null;
      $('backup-workspace').hidden = true; $('backup-login').hidden = false;
    }
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error || '请求失败'); error.status = response.status; throw error; }
    if (result.csrf) state.csrf = result.csrf;
    return result;
  }
  function markDirty() {
    state.dirty = true; state.ticket = null;
    $('restore-preview').hidden = true; controls();
  }
  function formatTime(value) { return value ? new Date(value).toLocaleString('zh-CN', { timeZone: 'Asia/Singapore', hour12: false }) + ' UTC+8' : '暂无'; }
  async function load() {
    loginPolicy(await api('/api/session'));
    const result = await api('/api/config');
    state.config = result.config; state.revision = result.revision; state.dirty = false; state.uncertain = false; state.ticket = null;
    const settings = state.config.backups;
    $('backup-enabled').checked = settings.enabled;
    $('backup-time').value = settings.time;
    $('backup-retention').value = settings.retain_count;
    $('backup-password').value = '';
    $('backup-password').placeholder = settings.password ? '已保存, 留空保留' : '设置至少 16 字符的独立恢复密码';
    $('backup-password-hint').textContent = settings.password ? '已有恢复密码, 服务不会回显.' : '保存恢复密码后才能创建自动或手动备份.';
    $('restore-preview').hidden = true;
    await list(); controls();
  }
  async function list() {
    const result = await api('/api/backups');
    $('backup-schedule').textContent = `下次备份: ${formatTime(result.next_at)}. 最近状态: ${result.last_state || '尚无记录'}${result.error ? ' / ' + result.error : ''}`;
    const root = $('backup-files'); root.replaceChildren();
    for (const item of result.backups || []) {
      const row = document.createElement('article'); row.className = 'run-row';
      const label = document.createElement('p'); label.textContent = `${formatTime(item.created_at)} / ${Math.ceil((item.size_bytes ?? item.size ?? 0) / 1024)} KiB`;
      const link = document.createElement('a'); link.className = 'button quiet'; link.textContent = '下载加密备份'; link.href = '/api/backups/' + encodeURIComponent(item.id); link.download = '';
      row.append(label, link); root.append(row);
    }
    if (!root.childElementCount) { const empty = document.createElement('p'); empty.className = 'muted small'; empty.textContent = '尚无备份. 保存恢复密码后可立即创建.'; root.append(empty); }
  }
  async function perform(action, write = false) {
    if (state.busy) return;
    state.busy = true; controls();
    try { await action(); }
    catch (error) {
      if (write && (!error.status || error.status >= 500)) {
        state.uncertain = true;
        message('请求结果尚未确认. 请先重新读取设置和备份列表, 确认结果后再操作.', true);
      } else message(window.CheckinPasskeys?.errorMessage(error) || error.message || '连接失败, 请重试读取状态.', true);
    } finally { state.busy = false; controls(); }
  }
  $('backup-login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    perform(async () => {
      const session = await api('/api/login', { method: 'POST', body: { password: $('backup-login-password').value } });
      $('backup-login-password').value = ''; state.csrf = session.csrf;
      $('backup-login').hidden = true; $('backup-workspace').hidden = false; await load();
    });
  });
  $('backup-passkey-login').addEventListener('click', () => perform(async () => {
    const session = await window.CheckinPasskeys.login(api);
    state.csrf = session.csrf;
    $('backup-login').hidden = true; $('backup-workspace').hidden = false;
    await load();
  }));
  $('backup-settings-form').addEventListener('input', markDirty);
  $('backup-settings-form').addEventListener('submit', (event) => {
    event.preventDefault();
    perform(async () => {
      const config = structuredClone(state.config);
      config.backups = { enabled: $('backup-enabled').checked, time: $('backup-time').value, retain_count: Number($('backup-retention').value), password: $('backup-password').value || state.config.backups.password };
      await api('/api/config', { method: 'PUT', body: { revision: state.revision, config } });
      await load(); message('备份设置已保存. 更改恢复密码只影响新备份.');
    }, true);
  });
  $('backup-create').addEventListener('click', () => perform(async () => {
    await api('/api/backups', { method: 'POST', body: { revision: state.revision } });
    await list(); message('加密备份已创建. 可下载另存.');
  }, true));
  $('backup-reload').addEventListener('click', () => {
    if (state.dirty && !window.confirm('重新读取会丢弃未保存的备份设置. 是否继续?')) return;
    perform(async () => { await load(); message('已重新读取设置和备份列表.'); });
  });
  $('backup-refresh-list').addEventListener('click', () => perform(list));
  $('restore-file').addEventListener('change', () => { state.ticket = null; $('restore-preview').hidden = true; controls(); });
  $('restore-password').addEventListener('input', () => { state.ticket = null; $('restore-preview').hidden = true; controls(); });
  $('backup-preview-form').addEventListener('submit', (event) => {
    event.preventDefault();
    perform(async () => {
      const file = $('restore-file').files[0];
      if (!file || file.size > 64 * 1024 * 1024) throw new Error('请选择不超过 64 MiB 的加密备份文件.');
      const body = new FormData(); body.append('revision', String(state.revision)); body.append('password', $('restore-password').value); body.append('file', file);
      const preview = await api('/api/backups/preview', { method: 'POST', body });
      state.ticket = preview.ticket;
      $('restore-preview-detail').textContent = `备份时间: ${formatTime(preview.created_at)}. 账户: ${preview.accounts ?? preview.account_count ?? preview.counts?.accounts ?? '未知'}. 运行记录: ${preview.runs ?? preview.run_count ?? preview.counts?.runs ?? '未知'}. 校验有效期: ${formatTime(preview.expires_at)}.`;
      $('restore-password').value = ''; $('restore-admin-password').value = ''; $('restore-confirm').checked = false;
      $('restore-preview').hidden = false; message('备份校验通过. 当前数据尚未替换.');
    });
  });
  $('backup-restore-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!state.ticket || !$('restore-confirm').checked) return;
    perform(async () => {
      const body = { revision: state.revision, ticket: state.ticket };
      if (state.reauthMethod === 'passkey') {
        try { body.reauth_token = await window.CheckinPasskeys.reauth(api); }
        catch (error) { error.status ||= 400; throw error; }
      } else body.admin_password = $('restore-admin-password').value;
      await api('/api/backups/restore', { method: 'POST', body });
      $('restore-admin-password').value = ''; state.ticket = null; state.dirty = false;
      window.location.assign('/backups?restored=1');
    }, true);
  });
  window.addEventListener('beforeunload', (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
  perform(async () => {
    const session = await api('/api/session'); state.csrf = session.csrf;
    $('backup-login').hidden = session.authenticated; $('backup-workspace').hidden = !session.authenticated;
    loginPolicy(session);
    if (session.authenticated) await load();
    if (new URLSearchParams(location.search).has('restored')) $('backup-login-message').textContent = '恢复完成, 自动任务已停用. 请使用当前管理认证方式重新登录并核对配置.';
  });
})();
