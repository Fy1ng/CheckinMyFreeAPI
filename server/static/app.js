'use strict';

(() => {
  const SECRET = '__UNCHANGED_SECRET__';
  const $ = (id) => document.getElementById(id);
  const copy = (value) => JSON.parse(JSON.stringify(value));
  const state = {
    csrf: '', authenticated: false, config: null, revision: null, dirty: false,
    tab: 'accounts', busy: false, configLoading: false, statusLoading: false,
    runsLoading: false, status: null, statusFresh: false, uncertain: null,
    savedIds: new Set(), savedIdentities: new Set(), savedProviders: new Set(),
    pollTimer: null, polling: false,
  };

  class ApiError extends Error {
    constructor(message, status = 0) { super(message); this.status = status; }
  }

  function el(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined) item.textContent = text;
    return item;
  }

  function button(text, className, action) {
    const item = el('button', className, text);
    item.type = 'button';
    item.addEventListener('click', action);
    return item;
  }

  function errorText(error) {
    return error instanceof ApiError ? error.message : '网络连接失败. 请检查本地服务是否仍在运行.';
  }

  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const headers = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (options.method && options.method !== 'GET' && path !== '/api/login') {
      headers['X-CSRF-Token'] = state.csrf;
    }
    let response;
    try {
      response = await fetch(path, {
        method: options.method || 'GET', headers, credentials: 'same-origin',
        cache: 'no-store', redirect: 'error', signal: controller.signal,
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
      let payload;
      try { payload = await response.json(); }
      catch (_) { throw new ApiError('服务返回了无法读取的响应. 请重新读取状态确认结果.', response.status); }
      if (!response.ok) {
        const message = typeof payload.error === 'string' ? payload.error : `请求失败, HTTP ${response.status}.`;
        if (response.status === 401 && path !== '/api/login') showLogin('登录已失效. 请重新登录.');
        throw new ApiError(message, response.status);
      }
      return payload;
    } finally { clearTimeout(timeout); }
  }

  function notice(message, type = '', action) {
    const box = $('global-message');
    box.replaceChildren(el('span', '', message));
    box.className = `notice ${type}`;
    box.hidden = !message;
    if (action) box.append(button(action.label, 'text-button', action.handler));
  }

  function markDirty() {
    state.dirty = true;
    updateControls();
  }

  function updateControls() {
    const available = !!state.config && !state.configLoading && state.authenticated;
    const blocked = state.busy || !!state.uncertain;
    $('save-button').disabled = !available || blocked || !state.dirty;
    $('save-button').textContent = state.busy ? '处理中...' : '保存配置';
    $('reload-config').disabled = !state.authenticated || state.busy || state.configLoading;
    $('reload-config').textContent = state.configLoading ? '读取中...' : '重新读取';
    $('start-button').disabled = !available || blocked || state.dirty || !state.statusFresh || !!state.status?.running;
    $('stop-button').disabled = blocked || !state.statusFresh || !state.status?.running || state.status?.run?.state === 'stopping';
    $('logout-button').disabled = state.busy;
    $('dirty-status').textContent = !available ? '配置尚未就绪' : state.uncertain ? '请先确认上次操作结果' : state.dirty ? '有未保存的修改' : '所有修改已保存';
    $('dirty-status').className = `dirty-status${state.dirty ? ' unsaved' : ''}${state.uncertain ? ' uncertain-lock' : ''}`;
    $('config-revision').textContent = state.revision === null ? '尚未读取配置' : `已保存版本 ${state.revision}`;
    if (state.config) {
      $('account-count').textContent = state.config.accounts.length;
      $('identity-count').textContent = Object.keys(state.config.identities).length;
      $('provider-count').textContent = Object.keys(state.config.providers).length;
    }
    if (state.uncertain) {
      $('save-hint').textContent = '上次写入结果不确定. 不要重复提交, 请先重新读取确认.';
    } else if (state.dirty) {
      $('save-hint').textContent = '修改只在当前页面. 保存后才会应用, 保存不会自动开始签到.';
    } else {
      $('save-hint').textContent = '敏感字段已隐藏. 输入新值替换, 使用清除按钮删除.';
    }
    let taskHint = '保存配置不会执行签到. 定时任务使用最近一次保存的配置.';
    if (state.status?.platform?.manual_supported === false) taskHint = '当前环境不支持人工登录. 请使用 Windows 本地有界面浏览器, 或 Linux 图形会话.';
    else if (state.status?.platform?.manual_mode === 'desktop') taskHint = '本机登录会使用已打开的 Chromium 窗口. 请在窗口中完成验证和登录, 程序会连续等待.';
    if (state.config?.browser?.headless) taskHint = '无头模式只尝试自动登录. 需要人工验证或登录时会停止该账号, 请关闭无头模式后再运行.';
    const manualRun = state.status?.run;
    if (state.status?.running && manualRun?.manual_transport === 'desktop') {
      const seconds = manualRun.manual_remaining_seconds;
      taskHint = `请在本机已打开的 Chromium 窗口完成验证, 登录和授权. ${Number.isFinite(seconds) ? `剩余约 ${seconds} 秒. ` : ''}验证后继续在同一窗口登录, 无需重新运行.`;
    }
    $('task-hint').textContent = state.dirty ? '请先保存当前修改, 再开始签到.' : taskHint;
  }

  function setBusy(value) {
    state.busy = value;
    $('config-form').inert = value;
    updateControls();
  }

  function setUncertain(kind, detail = '') {
    state.uncertain = kind;
    notice(`${detail ? `${detail} ` : ''}请求已发出, 但未能确认结果. 为避免重复执行, 请先重新读取确认.`, 'warning', {
      label: '重新读取确认', handler: kind === 'config' ? () => loadConfig(true) : reconcile,
    });
    updateControls();
  }

  function showLogin(message = '') {
    state.authenticated = false;
    state.csrf = '';
    stopPolling();
    $('workspace').hidden = true;
    $('login-view').hidden = false;
    $('logout-button').hidden = true;
    $('login-message').textContent = message;
    $('login-message').className = `inline-message${message ? ' error' : ''}`;
    $('login-button').disabled = false;
  }

  async function enterWorkspace(session) {
    state.authenticated = true;
    state.csrf = session.csrf;
    $('login-password').value = '';
    $('login-view').hidden = true;
    $('workspace').hidden = false;
    $('logout-button').hidden = false;
    if (state.uncertain === 'logout') state.uncertain = null;
    const configTask = state.config && state.dirty ? Promise.resolve(renderForm()) : loadConfig(false);
    await Promise.allSettled([configTask, loadStatus(), loadRuns()]);
    schedulePoll();
  }

  function normalizeConfig(config) {
    const result = copy(config);
    result.accounts ||= [];
    result.identities ||= {};
    result.providers ||= {};
    result.notifications ||= {};
    result.proxy_url ||= '';
    result.schedule ||= { enabled: false, interval_minutes: 360 };
    result.browser ||= {};
    const defaults = { headless: false, humanize: true, wait_timeout_ms: 60000, manual_timeout_seconds: 600, manual_total_timeout_seconds: 1800 };
    Object.entries(defaults).forEach(([key, value]) => { if (result.browser[key] === undefined) result.browser[key] = value; });
    return result;
  }

  async function loadConfig(askDiscard) {
    if (state.configLoading) return;
    if (askDiscard && state.dirty && !window.confirm('重新读取会丢弃当前未保存的修改. 是否继续?')) return;
    state.configLoading = true;
    $('config-form').inert = true;
    $('retry-config').disabled = true;
    updateControls();
    try {
      const data = await api('/api/config');
      state.config = normalizeConfig(data.config);
      state.revision = data.revision;
      state.savedIds = new Set(state.config.accounts.map((account) => account.id));
      state.savedIdentities = new Set(Object.keys(state.config.identities));
      state.savedProviders = new Set(Object.keys(state.config.providers));
      state.dirty = false;
      if (state.uncertain === 'config') { state.uncertain = null; notice('已读取服务器当前配置. 请核对保存结果.'); }
      else if (askDiscard) notice('已重新读取服务器当前配置.');
      $('config-error').hidden = true;
      $('config-form').hidden = false;
      renderForm();
    } catch (error) {
      if (state.config) notice(`读取失败, 当前草稿已保留. ${errorText(error)}`, 'error');
      else {
        $('config-error').hidden = false;
        $('config-error').querySelector('p').textContent = errorText(error);
        $('config-form').hidden = true;
      }
    } finally {
      state.configLoading = false;
      $('config-form').inert = state.busy;
      $('retry-config').disabled = false;
      updateControls();
    }
  }

  function formatTime(value) {
    if (!value) return '暂无';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }).replaceAll('/', '-');
  }

  function runLabel(runState) {
    return ({ running: '执行中', awaiting_login: '等待人工登录', succeeded: '已完成', success: '已完成', completed: '已完成', failed: '失败', error: '失败', cancelled: '已停止', canceled: '已停止', stopped: '已停止', interrupted: '已中断', stopping: '停止中' })[runState] || runState || '未运行';
  }

  function badge(runState) {
    const kind = ['running', 'awaiting_login', 'stopping'].includes(runState) ? 'running' : ['failed', 'error', 'interrupted'].includes(runState) ? 'error' : ['succeeded', 'success', 'completed'].includes(runState) ? 'success' : '';
    return el('span', `badge ${kind}`, runLabel(runState));
  }

  function explainError(code) {
    return ({ MANUAL_LOGIN_UNAVAILABLE: '当前环境无法进行人工登录', MANUAL_LOGIN_TIMED_OUT: '等待人工登录超时', MANUAL_LOGIN_REQUIRES_HEADED_BROWSER: '需要人工登录, 请关闭无头模式后再运行', OAUTH_BROWSER_CLOSED: '浏览器窗口已关闭, 登录未完成', IDENTITY_MANUAL_LOGIN_FAILED: '同一身份的前一个人工登录未完成' })[code] || code;
  }

  function renderStatus(data) {
    const run = data.run;
    const currentBadge = badge(run?.state);
    currentBadge.id = 'task-badge';
    $('task-badge').replaceWith(currentBadge);
    $('task-description').textContent = run ? `任务 #${run.id}, ${formatTime(run.started_at)} 开始.${run.error ? ` ${run.error}` : ''}${data.running && run.manual_transport === 'desktop' ? ' 正在等待本机浏览器中的人工登录.' : ''}` : '还没有运行中的任务. 配置完成后即可开始.';
    $('next-run').textContent = data.next_run_at ? `下次计划: ${formatTime(data.next_run_at)}` : '定时任务未启用, 或尚未安排下一次运行.';
    const link = $('manual-link');
    link.hidden = true;
    link.removeAttribute('href');
    if (data.running && run?.manual_url) {
      try {
        const url = new URL(run.manual_url, window.location.href);
        if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password) {
          link.href = url.href;
          link.hidden = false;
        }
      } catch (_) { /* Invalid URLs are never turned into navigation links. */ }
    }
    updateControls();
  }

  async function loadStatus() {
    if (state.statusLoading) return false;
    state.statusLoading = true;
    $('retry-status').disabled = true;
    try {
      const data = await api('/api/status');
      state.status = data;
      state.statusFresh = true;
      renderStatus(data);
      $('connection-status').textContent = '服务已连接';
      $('connection-status').className = 'connection-state';
      $('status-error').hidden = true;
      return true;
    } catch (error) {
      state.statusFresh = false;
      $('manual-link').hidden = true;
      $('manual-link').removeAttribute('href');
      $('connection-status').textContent = '状态读取失败';
      $('connection-status').className = 'connection-state offline';
      $('status-error').hidden = false;
      $('status-error').querySelector('span').textContent = errorText(error);
      return false;
    } finally {
      state.statusLoading = false;
      $('retry-status').disabled = false;
      updateControls();
    }
  }

  async function loadRuns() {
    if (state.runsLoading) return;
    state.runsLoading = true;
    $('refresh-runs').disabled = true;
    try {
      const data = await api('/api/runs');
      const list = $('runs-list');
      list.replaceChildren();
      if (!data.runs.length) list.append(el('p', 'muted small', '暂无运行记录. 首次执行后会显示在这里.'));
      data.runs.slice(0, 12).forEach((run) => {
        const row = el('div', 'run-row');
        const main = el('div', 'run-main');
        main.append(el('p', 'run-title', `任务 #${run.id}`));
        main.append(el('p', 'run-meta', formatTime(run.started_at)));
        if (run.finished_at) main.append(el('p', 'run-meta', `结束: ${formatTime(run.finished_at)}`));
        if (run.error) main.append(el('p', 'run-meta', run.error));
        if (run.summary && typeof run.summary === 'object') {
          if (typeof run.summary.success_count === 'number' && typeof run.summary.total_count === 'number') {
            main.append(el('p', 'run-meta', `成功 ${run.summary.success_count} / ${run.summary.total_count}`));
          }
          if (run.summary.notification_error) main.append(el('p', 'run-meta', '通知发送异常'));
          if (Array.isArray(run.summary.accounts) && run.summary.accounts.length) {
            const details = el('details', 'run-details');
            details.append(el('summary', '', '查看账号结果'));
            run.summary.accounts.forEach((account) => {
              if (account && typeof account === 'object') details.append(el('p', 'run-meta', `${account.name || account.id || '账号'}: ${account.success ? '成功' : '未完成'}${account.error ? `, ${explainError(account.error)}` : ''}`));
            });
            main.append(details);
          }
        }
        row.append(main, badge(run.state));
        list.append(row);
      });
    } catch (error) {
      const box = el('div', 'load-error');
      box.append(el('span', '', errorText(error)), button('重试', 'text-button', loadRuns));
      $('runs-list').replaceChildren(box);
    } finally {
      state.runsLoading = false;
      $('refresh-runs').disabled = false;
    }
  }

  function stopPolling() {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }

  function schedulePoll() {
    stopPolling();
    if (!state.authenticated || document.hidden) return;
    state.pollTimer = setTimeout(poll, 5000);
  }

  async function poll() {
    if (state.polling || !state.authenticated || document.hidden) return;
    state.polling = true;
    try { await Promise.allSettled([loadStatus(), loadRuns()]); }
    finally { state.polling = false; schedulePoll(); }
  }

  async function reconcile() {
    if (state.busy) return;
    if (state.uncertain === 'logout') {
      try {
        const session = await api('/api/session');
        state.uncertain = null;
        if (!session.authenticated) {
          state.config = null; state.revision = null; state.dirty = false;
          $('form-content').replaceChildren();
          showLogin('');
        } else {
          state.csrf = session.csrf;
          notice('当前管理会话仍然有效. 如需退出, 可再次点击退出.');
          updateControls();
        }
      } catch (error) { notice(errorText(error), 'error', { label: '重新读取确认', handler: reconcile }); }
      return;
    }
    const success = await loadStatus();
    await loadRuns();
    if (success && state.uncertain !== 'config') {
      state.uncertain = null;
      notice('已重新读取任务状态. 请核对当前任务和近期记录后再操作.');
      updateControls();
    }
  }

  function field(label, value, change, options = {}) {
    const wrap = el('label', `field${options.wide ? ' field-wide' : ''}`);
    const title = el('span', 'field-label', label);
    if (options.optional) title.append(el('span', 'optional', '可选'));
    wrap.append(title);
    const input = el(options.multiline ? 'textarea' : 'input');
    if (!options.multiline) input.type = options.type || 'text';
    input.value = value ?? '';
    if (options.placeholder) input.placeholder = options.placeholder;
    if (options.required) input.required = true;
    if (options.readOnly) input.readOnly = true;
    if (options.min !== undefined) input.min = options.min;
    if (options.max !== undefined) input.max = options.max;
    if (options.type === 'number') input.step = '1';
    input.autocomplete = options.autocomplete || 'off';
    input.addEventListener('input', () => {
      change(options.type === 'number' ? (input.value === '' ? null : Number(input.value)) : input.value);
      markDirty();
    });
    wrap.append(input);
    if (options.hint) wrap.append(el('p', 'field-hint', options.hint));
    return wrap;
  }

  function selectField(label, value, choices, change, options = {}) {
    const wrap = el('label', `field${options.wide ? ' field-wide' : ''}`);
    wrap.append(el('span', 'field-label', label));
    const select = el('select');
    choices.forEach(([key, name]) => {
      const option = el('option', '', name);
      option.value = key;
      select.append(option);
    });
    select.value = value ?? '';
    select.addEventListener('change', () => { change(select.value); markDirty(); });
    wrap.append(select);
    if (options.hint) wrap.append(el('p', 'field-hint', options.hint));
    return wrap;
  }

  function checkField(label, value, change, hint) {
    const wrap = el('div', 'field');
    const row = el('label', 'toggle-field');
    const input = el('input');
    input.type = 'checkbox';
    input.checked = !!value;
    input.addEventListener('change', () => { change(input.checked); markDirty(); });
    row.append(input, el('span', '', label));
    wrap.append(row);
    if (hint) wrap.append(el('p', 'field-hint', hint));
    return wrap;
  }

  function secretField(label, value, change, options = {}) {
    const wrap = el('div', `field${options.wide ? ' field-wide' : ''}`);
    const id = `secret-${++secretField.counter}`;
    const title = el('label', 'field-label', label);
    title.htmlFor = id;
    const input = el('input');
    input.id = id;
    input.type = 'password';
    input.autocomplete = 'new-password';
    input.spellcheck = false;
    input.value = value === SECRET || typeof value === 'object' ? '' : value || '';
    input.placeholder = value === SECRET || (value && typeof value === 'object') ? '已设置, 留空保留' : options.placeholder || '未设置';
    let explicitlyCleared = false;
    const secretStatus = el('div', 'secret-state');
    const status = el('span', '', value === SECRET || (value && typeof value === 'object') ? '已设置, 当前值不会回显' : value ? '将保存新值' : '未设置');
    input.addEventListener('input', () => {
      if (!input.value && value && !explicitlyCleared) {
        change(value);
        input.placeholder = '已设置, 留空保留';
        status.textContent = '留空保留原值, 删除请点击清除';
      } else {
        change(input.value);
        input.placeholder = '未设置';
        status.textContent = input.value ? '将保存新值' : explicitlyCleared ? '将清除已有值' : '未设置';
      }
      markDirty();
    });
    secretStatus.append(status, button('清除', 'text-button remove', () => {
      explicitlyCleared = true;
      input.value = '';
      input.placeholder = '未设置';
      status.textContent = '将清除已有值';
      change('');
      markDirty();
    }));
    wrap.append(title, input, secretStatus);
    if (options.hint) wrap.append(el('p', 'field-hint', options.hint));
    return wrap;
  }
  secretField.counter = 0;

  function proxyField(label, object, key, hint) {
    const wrap = el('div', 'field');
    const title = el('span', 'field-label', label);
    wrap.append(title);
    const row = el('div', 'proxy-control');
    const select = el('select');
    select.setAttribute('aria-label', `${label}模式`);
    [['', '沿用上级'], ['direct', '直连'], ['default', '默认代理'], ['custom', '指定代理']].forEach(([value, text]) => {
      const option = el('option', '', text); option.value = value; select.append(option);
    });
    const current = object[key];
    select.value = !current ? '' : ['direct', 'default'].includes(current) ? current : 'custom';
    const secret = secretField('代理 URL', select.value === 'custom' ? current : '', (value) => { object[key] = value; });
    secret.querySelector('label').hidden = true;
    secret.hidden = select.value !== 'custom';
    select.addEventListener('change', () => {
      if (select.value === '') delete object[key];
      else object[key] = select.value === 'custom' ? '' : select.value;
      secret.hidden = select.value !== 'custom';
      if (select.value === 'custom') {
        secret.querySelector('input').value = '';
        secret.querySelector('input').placeholder = 'http://127.0.0.1:7890';
        secret.querySelector('.secret-state span').textContent = '未设置';
      }
      markDirty();
    });
    row.append(select, secret);
    wrap.append(row);
    if (hint) wrap.append(el('p', 'field-hint', hint));
    return wrap;
  }

  function heading(title, description, addLabel, addAction) {
    const row = el('div', 'tab-heading');
    const text = el('div'); text.append(el('h3', '', title), el('p', '', description));
    row.append(text);
    if (addLabel) row.append(button(addLabel, 'button secondary', addAction));
    return row;
  }

  function card(title, index, remove) {
    const outer = el('section', 'config-card');
    const head = el('div', 'card-heading');
    const text = el('h4', 'card-title');
    text.append(el('span', 'card-index', String(index + 1).padStart(2, '0')), document.createTextNode(title));
    head.append(text, button('移除', 'text-button remove', remove));
    const grid = el('div', 'form-grid');
    outer.append(head, grid);
    return { outer, grid };
  }

  function advanced(title, children) {
    const details = el('details', 'details-box');
    details.append(el('summary', '', title));
    const grid = el('div', 'form-grid'); grid.append(...children); details.append(grid);
    return details;
  }

  function empty(container, title, description) {
    const item = el('div', 'empty-state'); item.append(el('h3', '', title), el('p', '', description)); container.append(item);
  }

  function uniqueKey(prefix, existing) {
    let index = 1;
    while (existing.includes(`${prefix}-${index}`)) index += 1;
    return `${prefix}-${index}`;
  }

  function renderAccounts(container) {
    container.append(heading('签到账号', '一个账号对应一个目标站点. OAuth 登录只选择身份别名, 不填写第三方平台密码.', '+ 添加账号', () => {
      state.config.accounts.push({ id: uniqueKey('account', state.config.accounts.map((item) => item.id)), name: '', provider: 'anyrouter', auth: { type: 'linuxdo', identity: '' } });
      markDirty(); renderForm();
    }));
    const cards = el('div', 'cards');
    if (!state.config.accounts.length) empty(cards, '添加第一个账号', '先在登录身份中添加 LinuxDo 或 GitHub 身份, 再将它关联到目标站点.');
    state.config.accounts.forEach((account, index) => {
      const { outer, grid } = card(account.name || account.id || '新账号', index, () => { state.config.accounts.splice(index, 1); markDirty(); renderForm(); });
      const providers = [...new Set(['anyrouter', 'agentrouter', ...Object.keys(state.config.providers), ...(account.provider ? [account.provider] : [])])];
      grid.append(
        field('账号名称', account.name, (value) => { account.name = value; }, { placeholder: '例如: 主账号', optional: true }),
        selectField('目标站点', account.provider || 'anyrouter', providers.map((name) => [name, ({ anyrouter: 'AnyRouter', agentrouter: 'AgentRouter' })[name] || name]), (value) => { account.provider = value; }),
        field('稳定 ID', account.id, (value) => { account.id = value; }, { required: true, readOnly: state.savedIds.has(account.id), hint: '用于关联登录态. 首次保存后固定, 不随名称变化.' }),
      );
      const type = account._uiAuth || account.auth?.type || (account.cookies ? 'cookie' : 'password');
      grid.append(selectField('认证方式', type, [['linuxdo', 'LinuxDo OAuth'], ['github', 'GitHub OAuth'], ['password', '站点邮箱密码'], ['cookie', '已有 Cookie']], (value) => {
        delete account.auth; delete account.email; delete account.password; delete account.cookies;
        if (['linuxdo', 'github'].includes(value)) account.auth = { type: value, identity: '' };
        else if (value === 'cookie') account.cookies = '';
        else { account.email = ''; account.password = ''; }
        account._uiAuth = value;
        renderForm();
      }));
      const activeType = account._uiAuth || type;
      if (['linuxdo', 'github'].includes(activeType)) {
        const identities = Object.entries(state.config.identities).filter(([, value]) => value.type === activeType).map(([alias]) => [alias, alias]);
        if (account.auth.identity && !identities.some(([key]) => key === account.auth.identity)) identities.push([account.auth.identity, `${account.auth.identity} (身份不存在或类型不匹配)`]);
        grid.append(selectField('登录身份', account.auth.identity, [['', '请选择身份'], ...identities], (value) => { account.auth.identity = value; }, { hint: identities.length ? '同一身份可关联多个站点账号.' : `尚无 ${activeType === 'linuxdo' ? 'LinuxDo' : 'GitHub'} 身份. 请先在登录身份中添加.` }));
      } else if (activeType === 'password') {
        grid.append(field('站点登录邮箱', account.email, (value) => { account.email = value; }, { type: 'email', autocomplete: 'off', placeholder: 'account@example.com' }));
        grid.append(secretField('站点密码', account.password, (value) => { account.password = value; }, { hint: '只填写目标站点密码, 不填写 LinuxDo 或 GitHub 密码.' }));
      } else {
        grid.append(secretField('Cookie', account.cookies, (value) => { account.cookies = value; }, { wide: true, placeholder: 'session=...; other=...', hint: '兼容已有登录态. 输入完整 Cookie header, 已保存值留空保留.' }));
      }
      grid.append(
        field('目标站点用户名', account.expected_username, (value) => { account.expected_username = value; }, { optional: activeType !== 'linuxdo' && activeType !== 'github', hint: 'OAuth 需要填写用户名或用户 ID, 以核验登录的账号.' }),
        field('目标站点用户 ID', account.api_user, (value) => { account.api_user = value; }, { optional: true, placeholder: '例如: 12345', hint: '两项均填写时必须同时匹配. Cookie 认证请提供用户 ID.' }),
      );
      outer.append(advanced('账号代理', [proxyField('代理', account, 'proxy', '沿用上级时按身份和站点配置解析. 共享同一身份的账号必须使用一致代理.')]));
      cards.append(outer);
    });
    container.append(cards);
  }

  function renderIdentities(container) {
    container.append(heading('登录身份', '身份代表同一个 LinuxDo 或 GitHub 用户. 首次登录由运行任务中的人工登录入口完成.', '+ 添加身份', () => {
      state.config.identities[uniqueKey('identity', Object.keys(state.config.identities))] = { type: 'linuxdo' };
      markDirty(); renderForm();
    }));
    const cards = el('div', 'cards');
    if (!Object.keys(state.config.identities).length) empty(cards, '还没有登录身份', '添加身份后, 在账号表单选择对应别名. 不需要导出 Cookie 或填写 OAuth 平台密码.');
    Object.entries(state.config.identities).forEach(([originalAlias, identity], index) => {
      let alias = originalAlias;
      const { outer, grid } = card(alias, index, () => { delete state.config.identities[alias]; markDirty(); renderForm(); });
      grid.append(
        field('身份别名', alias, (value) => {
          if (value === alias) return;
          if (Object.hasOwn(state.config.identities, value)) { notice('身份别名已存在. 请使用另一个别名.', 'warning'); renderForm(); return; }
          delete state.config.identities[alias]; Object.defineProperty(state.config.identities, value, { value: identity, configurable: true, writable: true, enumerable: true }); alias = value;
        }, { required: true, readOnly: state.savedIdentities.has(alias), hint: '用于关联账号. 首次保存后固定.' }),
        selectField('身份平台', identity.type, [['linuxdo', 'LinuxDo'], ['github', 'GitHub']], (value) => { identity.type = value; }),
        proxyField('身份代理', identity, 'proxy', '所有关联账号将共享该代理选择. 沿用上级时由目标站点决定.'),
      );
      const linked = state.config.accounts.filter((account) => account.auth?.identity === originalAlias);
      outer.append(el('p', 'hint-box', linked.length ? `关联账号: ${linked.map((account) => account.name || account.id).join(', ')}` : '尚未关联账号. 请在账号配置中选择该身份.'));
      cards.append(outer);
    });
    container.append(cards);
  }

  function renderProviders(container) {
    container.append(heading('自定义站点', '内置 AnyRouter 和 AgentRouter 可直接使用. 在这里添加其他站点, 或用相同别名覆盖内置参数.', '+ 添加站点', () => {
      state.config.providers[uniqueKey('site', Object.keys(state.config.providers))] = { domain: '', login_path: '/login', sign_in_path: '/api/user/sign_in', user_info_path: '/api/user/self', api_user_key: 'new-api-user', status_path: '/api/status', auth_state_path: '/api/oauth/state', oauth_client_ids: {}, use_proxy: false };
      markDirty(); renderForm();
    }));
    const cards = el('div', 'cards');
    if (!Object.keys(state.config.providers).length) empty(cards, '正在使用内置站点', 'AnyRouter 和 AgentRouter 的默认参数已准备好. 只有添加站点或调整参数时才需要配置这里.');
    Object.entries(state.config.providers).forEach(([originalAlias, provider], index) => {
      let alias = originalAlias;
      provider.oauth_client_ids ||= {};
      const { outer, grid } = card(alias, index, () => { delete state.config.providers[alias]; markDirty(); renderForm(); });
      grid.append(
        field('站点别名', alias, (value) => { if (value === alias) return; if (Object.hasOwn(state.config.providers, value)) { notice('站点别名已存在. 请使用另一个别名.', 'warning'); renderForm(); return; } delete state.config.providers[alias]; Object.defineProperty(state.config.providers, value, { value: provider, configurable: true, writable: true, enumerable: true }); alias = value; }, { required: true, readOnly: state.savedProviders.has(alias), hint: '例如: anyrouter, agentrouter 或 my-site.' }),
        field('站点域名', provider.domain, (value) => { provider.domain = value; }, { required: true, type: 'url', placeholder: 'https://example.com', hint: '使用纯 HTTPS origin, 不包含路径或查询参数.' }),
        field('登录页面', provider.login_path, (value) => { provider.login_path = value; }, { placeholder: '/login', optional: true }),
        field('签到接口', provider.sign_in_path, (value) => { provider.sign_in_path = value || null; }, { placeholder: '/api/user/sign_in', optional: true, hint: '留空表示不额外调用签到接口.' }),
        field('用户信息接口', provider.user_info_path, (value) => { provider.user_info_path = value; }, { placeholder: '/api/user/self', optional: true }),
        field('用户 ID 请求头', provider.api_user_key, (value) => { provider.api_user_key = value; }, { placeholder: 'new-api-user', optional: true }),
        checkField('使用默认代理', provider.use_proxy, (value) => { provider.use_proxy = value; }, '需在定时与浏览器中设置默认代理 URL.'),
      );
      outer.append(advanced('OAuth 和浏览器参数', [
        field('站点状态接口', provider.status_path, (value) => { provider.status_path = value; }, { placeholder: '/api/status', optional: true }),
        field('OAuth state 接口', provider.auth_state_path, (value) => { provider.auth_state_path = value; }, { placeholder: '/api/oauth/state', optional: true }),
        field('LinuxDo client ID', provider.oauth_client_ids.linuxdo, (value) => { provider.oauth_client_ids.linuxdo = value; }, { optional: true, hint: '通常从站点状态接口读取, 必要时覆盖.' }),
        field('GitHub client ID', provider.oauth_client_ids.github, (value) => { provider.oauth_client_ids.github = value; }, { optional: true }),
        selectField('WAF Cookie 处理', provider.bypass_method || '', [['', '不启用'], ['waf_cookies', '读取站点 WAF Cookie']], (value) => { provider.bypass_method = value || null; }),
        field('WAF Cookie 名称', (provider.waf_cookie_names || []).join(', '), (value) => { provider.waf_cookie_names = value.split(',').map((part) => part.trim()).filter(Boolean); }, { optional: true, hint: '多个名称用英文逗号分隔.' }),
        checkField('保留浏览器 profile', provider.persist_profile, (value) => { provider.persist_profile = value; }, '安全模式仍使用加密登录态快照.'),
      ]));
      cards.append(outer);
    });
    container.append(cards);
  }

  const notificationGroups = [
    ['电子邮件', [
      ['EMAIL_USER', '发件邮箱'], ['EMAIL_PASS', '邮箱应用密码', true], ['EMAIL_TO', '收件邮箱'], ['EMAIL_SENDER', '发件人地址'], ['CUSTOM_SMTP_SERVER', 'SMTP 服务器'],
    ]],
    ['机器人 Webhook', [
      ['DINGDING_WEBHOOK', '钉钉 Webhook', true], ['FEISHU_WEBHOOK', '飞书 Webhook', true], ['WEIXIN_WEBHOOK', '企业微信 Webhook', true],
    ]],
    ['PushPlus / Server 酱', [
      ['PUSHPLUS_TOKEN', 'PushPlus token', true], ['SERVERPUSHKEY', 'Server 酱 send key', true],
    ]],
    ['Telegram', [
      ['TELEGRAM_BOT_TOKEN', 'Bot token', true], ['TELEGRAM_CHAT_ID', 'Chat ID'],
    ]],
    ['Gotify', [
      ['GOTIFY_URL', '服务器 URL', true], ['GOTIFY_TOKEN', '应用 token', true], ['GOTIFY_PRIORITY', '消息优先级'],
    ]],
    ['Bark', [
      ['BARK_KEY', '设备 key', true], ['BARK_SERVER', '服务器 URL', true],
    ]],
    ['Fy1Push', [
      ['FY1PUSH_SERVER', '服务器 URL'], ['FY1PUSH_TOKEN', '发送 token', true], ['FY1PUSH_CHANNEL', '消息分组'],
    ]],
  ];

  function renderNotifications(container) {
    container.append(heading('通知渠道', '填写需要启用的渠道, 留空则不发送. 通知可能在真实签到或等待人工登录时发出, 保存不会发送测试通知.'));
    notificationGroups.forEach(([title, fields], index) => {
      const group = el('details', 'notification-group');
      group.open = index === 0 || fields.some(([key]) => state.config.notifications[key]);
      group.append(el('summary', '', title));
      const grid = el('div', 'form-grid');
      fields.forEach(([key, label, secret]) => {
        const value = state.config.notifications[key];
        const update = (next) => { state.config.notifications[key] = next; };
        const options = {
          optional: true,
          hint: key,
          placeholder: key === 'BARK_SERVER' ? 'https://api.day.app' : key === 'GOTIFY_PRIORITY' ? '9 (1-10)' : '',
          ...{
            FY1PUSH_SERVER: { placeholder: 'https://push.example.com', hint: 'FY1PUSH_SERVER. 留空禁用. 使用 HTTPS 服务根地址, 本机测试可用 HTTP loopback; 也兼容 /v1/push 后缀. 不含凭据, 查询参数或片段.' },
            FY1PUSH_TOKEN: { hint: 'FY1PUSH_TOKEN. 使用发送 token, 通过 Bearer 认证. 已保存值留空保留, 点击清除才删除.' },
            FY1PUSH_CHANNEL: { placeholder: '签到', hint: 'FY1PUSH_CHANNEL. 留空默认签到, 允许 1 至 24 个 Unicode 字母, 数字或 -_.' },
          }[key],
        };
        grid.append(secret || value === SECRET ? secretField(label, value, update, options) : field(label, value, update, options));
      });
      group.append(grid);
      if (title === 'Fy1Push') group.append(el('p', 'hint-box', '标题含分组前缀最多 40 字符, 过长时截断. 正文超过 100 字符时仅发送摘要, 完整执行记录请查看 WebUI. accepted=true 只表示服务端已接收, 不代表手机已到达.'));
      container.append(group);
    });
    container.append(el('p', 'hint-box', '邮箱采用 SMTP SSL, 端口 465. Telegram 需要可访问其 API 的网络. 已保存的密钥留空保留, 点击清除才删除.'));
  }

  function renderRuntime(container) {
    container.append(heading('定时与浏览器', '定时任务由当前服务调度, 服务停止期间不会运行. 时间以浏览器所在时区显示.'));
    const schedule = state.config.schedule;
    const browser = state.config.browser;
    const scheduling = el('section', 'runtime-group');
    scheduling.append(el('h3', '', '运行计划'));
    const scheduleGrid = el('div', 'form-grid');
    scheduleGrid.append(
      checkField('启用定时签到', schedule.enabled, (value) => { schedule.enabled = value; }, '保存后生效. 同一时间只运行一个签到任务.'),
      field('运行间隔, 分钟', schedule.interval_minutes, (value) => { schedule.interval_minutes = value; }, { type: 'number', min: 30, max: 10080, required: true, hint: '允许 30 至 10080 分钟. 请根据站点规则设置合理间隔.' }),
    );
    scheduling.append(scheduleGrid);
    const proxy = el('section', 'runtime-group'); proxy.append(el('h3', '', '默认代理'));
    proxy.append(secretField('代理 URL', state.config.proxy_url, (value) => { state.config.proxy_url = value; }, { placeholder: 'http://127.0.0.1:7890', hint: '供选择默认代理的账号, 身份和站点使用. 留空不启用默认代理.' }));
    const browsing = el('section', 'runtime-group'); browsing.append(el('h3', '', '浏览器与人工登录'));
    const browserGrid = el('div', 'form-grid');
    browserGrid.append(
      checkField('使用无头浏览器', browser.headless, (value) => { browser.headless = value; }, '人工登录需要关闭此项. Windows 操作本机窗口, Linux 通过 WebUI 接管有界面浏览器.'),
      checkField('启用自然交互', browser.humanize, (value) => { browser.humanize = value; }),
      field('页面等待上限, 毫秒', browser.wait_timeout_ms, (value) => { browser.wait_timeout_ms = value; }, { type: 'number', min: 1000, max: 120000, required: true }),
      field('单次人工登录上限, 秒', browser.manual_timeout_seconds, (value) => { browser.manual_timeout_seconds = value; }, { type: 'number', min: 30, max: 1800, required: true }),
      field('整次任务人工登录总上限, 秒', browser.manual_total_timeout_seconds, (value) => { browser.manual_total_timeout_seconds = value; }, { type: 'number', min: 30, max: 3600, required: true, hint: '应不小于单次人工登录上限.' }),
    );
    browsing.append(browserGrid);
    container.append(scheduling, proxy, browsing);
  }

  const renderers = { accounts: renderAccounts, identities: renderIdentities, providers: renderProviders, notifications: renderNotifications, runtime: renderRuntime };

  function renderForm() {
    if (!state.config) return;
    const container = $('form-content'); container.replaceChildren();
    renderers[state.tab](container);
    document.querySelectorAll('[data-tab]').forEach((item) => {
      item.classList.toggle('active', item.dataset.tab === state.tab);
      if (item.dataset.tab === state.tab) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    });
    updateControls();
  }

  function validateDraft() {
    const config = state.config;
    const ids = new Set();
    for (const account of config.accounts) {
      if (typeof account.id !== 'string' || !account.id || account.id.length > 128 || account.id.trim() !== account.id) return '账号稳定 ID 不能为空, 不能包含首尾空白, 且不能超过 128 个字符.';
      if (ids.has(account.id)) return `账号稳定 ID 重复: ${account.id}`;
      ids.add(account.id);
      if (account.auth && (!account.auth.identity || !Object.hasOwn(config.identities, account.auth.identity) || config.identities[account.auth.identity].type !== account.auth.type)) return `账号 ${account.name || account.id} 需要选择类型匹配的登录身份.`;
      if (account.auth && !account.expected_username && !account.api_user) return `账号 ${account.name || account.id} 需要填写目标站点用户名或用户 ID.`;
    }
    for (const [alias, identity] of Object.entries(config.identities)) {
      if (!alias.trim()) return '身份别名不能为空.';
      if (!['linuxdo', 'github'].includes(identity.type)) return `身份 ${alias} 的平台类型无效.`;
    }
    for (const [alias, provider] of Object.entries(config.providers)) {
      if (!alias.trim()) return '站点别名不能为空.';
      try {
        const url = new URL(provider.domain);
        if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) return `站点 ${alias} 的域名必须是纯 HTTPS origin, 例如 https://example.com.`;
      } catch (_) { return `请为站点 ${alias} 填写有效的 HTTPS 域名.`; }
    }
    const ranges = [
      [config.schedule.interval_minutes, 30, 10080, '运行间隔'],
      [config.browser.wait_timeout_ms, 1000, 120000, '页面等待上限'],
      [config.browser.manual_timeout_seconds, 30, 1800, '单次人工登录上限'],
      [config.browser.manual_total_timeout_seconds, 30, 3600, '人工登录总上限'],
    ];
    for (const [value, min, max, label] of ranges) if (!Number.isInteger(value) || value < min || value > max) return `${label} 需要为 ${min} 至 ${max} 之间的整数.`;
    if (config.browser.manual_total_timeout_seconds < config.browser.manual_timeout_seconds) return '整次任务人工登录总上限不能小于单次人工登录上限.';
    return '';
  }

  function cleanConfig() {
    const config = copy(state.config);
    config.accounts.forEach((account) => {
      delete account._uiAuth;
      for (const key of ['name', 'api_user', 'proxy']) if (account[key] === '') delete account[key];
    });
    Object.values(config.identities).forEach((identity) => { if (identity.proxy === '') delete identity.proxy; });
    Object.values(config.providers).forEach((provider) => {
      for (const key of ['login_path', 'user_info_path', 'status_path', 'auth_state_path', 'api_user_key']) if (provider[key] === '') delete provider[key];
      Object.entries(provider.oauth_client_ids || {}).forEach(([key, value]) => { if (!value) delete provider.oauth_client_ids[key]; });
    });
    return config;
  }

  async function saveConfig(event) {
    event.preventDefault();
    if (!state.config || !state.dirty || state.busy || state.uncertain) return;
    const problem = validateDraft();
    if (problem) { notice(problem, 'error'); return; }
    setBusy(true);
    try {
      const data = await api('/api/config', { method: 'PUT', body: { config: cleanConfig(), revision: state.revision } });
      state.config = normalizeConfig(data.config);
      state.revision = data.revision;
      state.savedIds = new Set(state.config.accounts.map((account) => account.id));
      state.savedIdentities = new Set(Object.keys(state.config.identities));
      state.savedProviders = new Set(Object.keys(state.config.providers));
      state.dirty = false;
      renderForm();
      notice('配置已保存. 本次保存没有执行签到.');
      await loadStatus();
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain('config', errorText(error));
      else if (error.status === 409) notice(`保存冲突, 当前草稿已保留. ${errorText(error)} 请重新读取前先保留所需修改.`, 'warning');
      else notice(errorText(error), 'error');
    } finally { setBusy(false); }
  }

  async function taskAction(stop) {
    if (state.busy || state.uncertain || !state.statusFresh) return;
    if (!stop && state.dirty) { notice('请先保存当前修改, 再开始签到.', 'warning'); return; }
    setBusy(true);
    try {
      await api(stop ? '/api/runs/stop' : '/api/runs', { method: 'POST', body: stop ? {} : { revision: state.revision } });
      notice(stop ? '已请求停止任务. 请等待运行状态更新.' : '签到任务已启动. 请留意当前任务状态和人工登录入口.');
      await Promise.allSettled([loadStatus(), loadRuns()]);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain(stop ? 'stop' : 'run', errorText(error));
      else { notice(errorText(error), error.status === 409 ? 'warning' : 'error'); await loadStatus(); }
    } finally { setBusy(false); }
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if ($('login-button').disabled) return;
    $('login-button').disabled = true;
    $('login-message').textContent = '正在登录...';
    $('login-message').className = 'inline-message';
    try { await enterWorkspace(await api('/api/login', { method: 'POST', body: { password: $('login-password').value } })); }
    catch (error) {
      $('login-message').textContent = errorText(error);
      $('login-message').className = 'inline-message error';
    } finally { $('login-button').disabled = false; }
  });

  $('logout-button').addEventListener('click', async () => {
    if (state.dirty && !window.confirm('退出会丢弃未保存的修改. 是否继续?')) return;
    setBusy(true);
    try {
      await api('/api/logout', { method: 'POST', body: {} });
      state.config = null; state.revision = null; state.dirty = false; state.uncertain = null;
      $('form-content').replaceChildren();
      $('runs-list').replaceChildren();
      $('manual-link').removeAttribute('href');
      notice('');
      showLogin('');
    } catch (error) {
      if (state.authenticated) setUncertain('logout', errorText(error));
      else { state.config = null; state.revision = null; state.dirty = false; }
    }
    finally { setBusy(false); }
  });

  $('config-nav').addEventListener('click', (event) => {
    const target = event.target.closest('[data-tab]');
    if (!target || state.busy) return;
    state.tab = target.dataset.tab;
    renderForm();
  });
  $('config-form').addEventListener('submit', saveConfig);
  $('reload-config').addEventListener('click', () => loadConfig(true));
  $('retry-config').addEventListener('click', () => loadConfig(false));
  $('retry-status').addEventListener('click', loadStatus);
  $('refresh-runs').addEventListener('click', loadRuns);
  $('start-button').addEventListener('click', () => taskAction(false));
  $('stop-button').addEventListener('click', () => taskAction(true));
  window.addEventListener('beforeunload', (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stopPolling(); else if (state.authenticated) poll(); });

  async function boot() {
    $('login-button').disabled = true;
    try {
      const session = await api('/api/session');
      if (session.authenticated) await enterWorkspace(session);
      else showLogin('');
    } catch (error) { showLogin(errorText(error)); }
  }
  boot();
})();
