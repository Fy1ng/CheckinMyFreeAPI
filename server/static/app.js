'use strict';

(() => {
  const SECRET = '__UNCHANGED_SECRET__';
  const $ = (id) => document.getElementById(id);
  const copy = (value) => JSON.parse(JSON.stringify(value));
  const state = {
    csrf: '', authenticated: false, config: null, revision: null, dirty: false,
    tab: 'accounts', busy: false, configLoading: false, statusLoading: false,
    runsLoading: false, status: null, statusFresh: false, uncertain: null, resolveAccount: null,
    savedIds: new Set(), migration: null, acknowledgedMigrations: new Set(), focusAccount: new URL(window.location.href).searchParams.get('account'),
    pollTimer: null, polling: false, expanded: new Map(), cardHeaders: [], runViews: new Map(),
    view: window.location.pathname === '/status' ? 'status' : 'manage',
    balances: null, balancesLoading: false, balanceViews: new Map(),
    automation: null, automationLoading: false,
    authPolicy: {}, loginBusy: false, runtime: null, runtimeBusy: false, backend: '',
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
    return error instanceof ApiError ? explainError(error.message) : '网络连接失败. 请检查服务是否仍在运行以及网络是否可达.';
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
      if (response.headers.get('X-Checkin-Runtime') === 'go') state.backend = 'go';
      try { payload = await response.json(); }
      catch (_) { throw new ApiError('服务返回了无法读取的响应. 请重新读取状态确认结果.', response.status); }
      if (!response.ok) {
        let message = typeof payload.error === 'string' ? payload.error : `请求失败, HTTP ${response.status}.`;
        if (response.status === 401 && path !== '/api/login' && !path.startsWith('/api/passkey/login/')) { showLogin(state.authPolicy.local_mode ? '本地服务暂时不可用. 请重新读取状态.' : '登录已失效. 请重新登录.'); refreshLoginPolicy(); }
        else if (response.status === 403 && state.authPolicy.local_mode && path !== '/api/session') { message = '本地页面状态已更新. 请重新读取后再操作.'; refreshLoginPolicy(); }
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
    state.cardHeaders.forEach((refresh) => refresh());
    updateControls();
  }

  function accountRunBlocked(accountId) {
    const account = state.config?.accounts.find((entry) => entry.id === accountId);
    const attention = state.status?.attention?.[accountId];
    if (!account?.enabled || !state.savedIds.has(accountId) || attention?.outcome === 'uncertain') return true;
    if (attention?.outcome !== 'rate_limited') return false;
    const retryAt = typeof attention.retry_at === 'number' ? attention.retry_at * 1000 : attention.retry_at;
    return !retryAt || !Number.isFinite(new Date(retryAt).getTime()) || new Date(retryAt).getTime() > Date.now();
  }

  function updateControls() {
    const available = !!state.config && !state.configLoading && state.authenticated;
    const blocked = state.busy || !!state.uncertain;
    $('save-button').disabled = !available || blocked || !state.dirty;
    $('save-button').textContent = state.busy ? '处理中...' : '保存配置';
    $('reload-config').disabled = !state.authenticated || state.busy || state.configLoading;
    $('reload-config').textContent = state.configLoading ? '读取中...' : '重新读取';
    $('start-button').disabled = !available || blocked || state.dirty || !state.statusFresh || !!state.status?.running;
    document.querySelectorAll('[data-account-run]').forEach((item) => {
      const account = state.config?.accounts.find((entry) => entry.id === item.dataset.accountRun);
      const attention = state.status?.attention?.[item.dataset.accountRun];
      item.setAttribute('aria-label', `签到账号 ${account?.name || account?.id || '新账号'}`);
      item.disabled = !available || blocked || state.dirty || !state.statusFresh || !!state.status?.running || accountRunBlocked(item.dataset.accountRun);
      item.title = !state.savedIds.has(account?.id) ? '请先保存此账号' : !account?.enabled ? '此账号已停用' : state.dirty ? '请先保存当前修改' : attention?.outcome === 'uncertain' ? '请先核对结果并解除暂停' : item.disabled ? '请等待当前操作完成并确认状态' : '仅签到此账号';
    });
    $('stop-button').disabled = blocked || !state.statusFresh || !state.status?.running || state.status?.run?.state === 'stopping';
    $('logout-button').disabled = state.busy;
    const balanceBlocked = !available || blocked || state.dirty || !state.statusFresh || !!state.status?.running || !!state.balances?.refreshing;
    $('refresh-balances').disabled = balanceBlocked;
    $('refresh-balances').textContent = state.balances?.refreshing || (state.status?.running && state.status?.run?.kind === 'balance') ? '正在采集...' : '刷新余额';
    document.querySelectorAll('[data-balance-refresh]').forEach((item) => {
      item.disabled = balanceBlocked || item.dataset.enabled !== 'true';
      item.title = state.dirty ? '请先保存当前修改' : item.dataset.enabled !== 'true' ? '此账号已停用' : balanceBlocked ? '请等待当前任务结束并确认状态' : '仅查询此账号的余额';
    });
    document.querySelectorAll('[data-send-summary]').forEach((item) => {
      item.disabled = !available || blocked || state.dirty || !state.statusFresh || !!state.status?.running;
      item.textContent = state.status?.running && state.status?.run?.kind === 'summary' ? '正在发送日报...' : '发送今日日报';
      item.title = state.dirty ? '请先保存当前修改' : item.disabled ? '请等待当前操作完成并确认状态' : '通过已配置的通知渠道发送今日日报';
    });
    $('dirty-status').textContent = !available ? '配置尚未就绪' : state.uncertain ? '请先确认上次操作结果' : state.dirty ? '有未保存的修改' : '所有修改已保存';
    $('dirty-status').className = `dirty-status${state.dirty ? ' unsaved' : ''}${state.uncertain ? ' uncertain-lock' : ''}`;
    $('config-revision').textContent = state.revision === null ? '尚未读取配置' : `已保存版本 ${state.revision}`;
    if (state.config) {
      $('account-count').textContent = state.config.accounts.length;
    }
    if (state.uncertain) {
      $('save-hint').textContent = '上次写入结果不确定. 不要重复提交, 请先重新读取确认.';
    } else if (state.dirty) {
      $('save-hint').textContent = '修改只在当前页面. 保存后才会应用, 保存不会自动开始签到.';
    } else {
      $('save-hint').textContent = '敏感字段已隐藏. 输入新值替换, 使用清除按钮删除.';
    }
    $('task-hint').textContent = state.dirty ? '请先保存当前修改, 再开始签到.' : '使用 HTTP 执行. 凭据或访问问题处理后可手动重试. 结果不确定的账号需先核对并解除暂停, 请求限流需等待期限结束.';
    document.querySelectorAll('[data-account-attention]').forEach((item) => {
      const accountId = item.dataset.accountAttention;
      const attention = state.status?.attention?.[accountId];
      item.hidden = !attention;
      if (!attention) return;
      item.querySelector('[data-attention-message]').textContent = `${runLabel(attention.outcome)}: ${explainError(attention.reason)}${attention.retry_at ? `. 可重试时间: ${formatTime(attention.retry_at)}` : ''}`;
      const resolve = item.querySelector('[data-account-resolve]');
      resolve.hidden = attention.outcome !== 'uncertain';
      resolve.disabled = !available || blocked || state.dirty || !state.savedIds.has(accountId) || !state.statusFresh || !!state.status?.running;
    });
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

  function renderLoginPolicy(session = state.authPolicy) {
    state.authPolicy = { ...state.authPolicy, ...(session || {}) };
    state.authPolicy.local_mode = session.local_mode === true;
    const local = state.authPolicy.local_mode === true;
    document.querySelectorAll('a[href="/security"]').forEach((item) => { item.hidden = local; });
    $('logout-button').hidden = local || !state.authenticated;
    state.authPolicy.setup_required = session.setup_required === true;
    const setup = state.authPolicy.setup_required;
    $('login-confirm-controls').hidden = !setup;
    $('login-confirm-password').required = setup;
    $('login-confirm-password').disabled = !setup || state.loginBusy;
    $('login-password').autocomplete = setup ? 'new-password' : 'current-password';
    $('login-password').minLength = setup ? 16 : 1;
    $('login-button').textContent = setup ? '设置密码并进入' : '登录';
    if (setup) state.csrf = state.authPolicy.setup_csrf || '';
    const password = state.authPolicy.password_login_allowed ?? (state.authPolicy.auth_mode !== 'passkey' || state.authPolicy.reauth_method === 'password');
    const passkey = state.authPolicy.passkey_available === true;
    $('password-login-controls').hidden = !password;
    $('login-password').disabled = !password || state.loginBusy;
    $('login-password').required = password;
    $('login-button').disabled = !password || state.loginBusy;
    $('passkey-login-button').hidden = !passkey && state.authPolicy.auth_mode !== 'passkey';
    $('passkey-login-button').disabled = state.loginBusy || !passkey || state.authPolicy.passkey_origin_allowed === false || !window.CheckinPasskeys?.supported();
    $('login-method-hint').textContent = !password ? '此入口仅允许 Passkey 登录. 请使用已绑定的设备或安全密钥.' : state.authPolicy.auth_mode === 'passkey' ? '当前为本机恢复入口, 可使用管理密码. 公网入口仍仅允许 Passkey.' : '请输入管理密码, 或使用已绑定的 Passkey.';
    if (state.authPolicy.auth_mode === 'passkey' && (!passkey || state.authPolicy.passkey_origin_allowed === false)) $('login-method-hint').textContent += ' 当前地址没有匹配的密钥, 请打开配置的 HTTPS 管理入口或通过 SSH 恢复.';
    else if (passkey && !window.CheckinPasskeys?.supported()) $('login-method-hint').textContent += ' 当前浏览器或地址不支持 Passkey, 请使用支持 WebAuthn 的浏览器和 HTTPS 入口.';
    if (setup) $('login-method-hint').textContent = '首次使用, 请设置 16 至 512 字符的管理密码. 仅允许从本机或 SSH 转发入口初始化.';
  }

  async function refreshLoginPolicy() {
    try {
      const wasLocal = state.authPolicy.local_mode;
      const session = await api('/api/session'); renderLoginPolicy(session);
      if (session.local_mode && session.csrf) state.csrf = session.csrf;
      else if (wasLocal && !session.authenticated) showLogin('此服务需要管理身份验证.');
    }
    catch (_) { /* Keep the last known mode until the session endpoint is reachable. */ }
  }

  function showLogin(message = '') {
    if (state.authPolicy.local_mode) {
      $('login-view').hidden = true; $('workspace').hidden = false; $('logout-button').hidden = true;
      notice(message || '本地服务暂时不可用. 请重新读取状态.', 'error');
      return;
    }
    state.authenticated = false;
    state.csrf = '';
    stopPolling();
    $('workspace').hidden = true;
    $('login-view').hidden = false;
    $('logout-button').hidden = true;
    $('login-message').textContent = message;
    $('login-message').className = `inline-message${message ? ' error' : ''}`;
    renderLoginPolicy();
  }

  async function enterWorkspace(session) {
    renderLoginPolicy(session);
    state.authenticated = true;
    state.csrf = session.csrf;
    $('login-password').value = '';
    $('login-confirm-password').value = '';
    $('login-view').hidden = true;
    $('workspace').hidden = false;
    $('logout-button').hidden = session.local_mode === true;
    renderWorkspaceView();
    if (state.uncertain === 'logout') state.uncertain = null;
    const configTask = state.config && state.dirty ? Promise.resolve(renderForm()) : loadConfig(false);
    await Promise.allSettled([configTask, loadStatus(), loadRuns(), loadLocalRuntime(), ...(state.view === 'status' ? [loadBalances(), loadAutomation()] : [])]);
    schedulePoll();
  }

  function normalizeConfig(config) {
    const result = copy(config);
    result.schema_version = 2;
    result.accounts ||= [];
    result.accounts.forEach((account) => { if (account.enabled === undefined) account.enabled = true; });
    result.notifications ||= {};
    result.proxy_url ||= '';
    result.schedule ||= { enabled: false, interval_minutes: 360 };
    result.schedule.mode ||= 'interval';
    result.schedule.cron ||= '0 8 * * *';
    result.monitoring ||= { enabled: true, interval_minutes: 60 };
    result.http ||= { timeout_seconds: 30 };
    result.webui_url ||= '';
    result.automation ||= {};
    result.automation.low_balance = { enabled: false, threshold: 1, cooldown_minutes: 360, ...result.automation.low_balance };
    result.automation.recovery = { enabled: false, cooldown_minutes: 60, ...result.automation.recovery };
    result.automation.daily_summary = { enabled: false, time: '23:55', ...result.automation.daily_summary };
    return result;
  }

  function migrationNotice(data) {
    state.migration = data.migration || null;
    if (!state.migration) return;
    const key = `newapi.migration.acknowledged:${state.migration.from_schema}:${state.migration.source_revision}`;
    let acknowledged = state.acknowledgedMigrations.has(key);
    try { acknowledged ||= localStorage.getItem(key) === '1'; }
    catch (_) { /* Storage may be unavailable; the current page still remembers acknowledgement. */ }
    if (acknowledged) return;
    notice('旧配置已保留并转换为 HTTP 配置. 不兼容的账号已停用, 请展开账号重新配置凭据后启用. 原有数据不会自动清空.', 'warning', {
      label: '我已知晓', handler: () => {
        state.acknowledgedMigrations.add(key);
        try { localStorage.setItem(key, '1'); }
        catch (_) { /* Acknowledgement remains effective for this page without storage. */ }
        notice('');
      },
    });
    $('global-message').classList.add('migration-notice');
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
      state.dirty = false;
      if (state.uncertain === 'config') { state.uncertain = null; notice('已读取服务器当前配置. 请核对保存结果.'); }
      else if (askDiscard) notice('已重新读取服务器当前配置.');
      migrationNotice(data);
      $('config-error').hidden = true;
      $('config-form').hidden = false;
      if (state.focusAccount && state.config.accounts.some((account) => account.id === state.focusAccount)) {
        state.tab = 'accounts';
        state.expanded.set(`account:${state.focusAccount}`, true);
      }
      renderForm();
      if (state.focusAccount) {
        const target = Array.from(document.querySelectorAll('[data-account-id]')).find((item) => item.dataset.accountId === state.focusAccount);
        target?.scrollIntoView({ block: 'nearest' });
        target?.querySelector('input')?.focus({ preventScroll: true });
        state.focusAccount = null;
      }
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
    const date = new Date(typeof value === 'number' && value < 1e12 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }).replaceAll('/', '-');
  }

  function runLabel(runState) {
    return ({ running: '执行中', succeeded: '已完成', success: '请求已完成', already_checked_in: '今日已签到', failed: '失败', needs_attention: '待处理', needs_credentials: '待更新凭据', blocked: '访问受阻', rate_limited: '请求限流', skipped: '已跳过', uncertain: '结果待核对', cancelled: '已停止', interrupted: '已中断', stopping: '停止中' })[runState] || runState || '未运行';
  }

  function badge(runState) {
    const kind = ['running', 'stopping'].includes(runState) ? 'running' : ['failed', 'interrupted'].includes(runState) ? 'error' : runState === 'succeeded' ? 'success' : ['needs_attention', 'uncertain'].includes(runState) ? 'warning' : '';
    return el('span', `badge ${kind}`, runLabel(runState));
  }

  function explainError(code) {
    return ({
      CREDENTIALS_REQUIRED: '缺少凭据, 请更新账号配置后手动重试',
      AUTH_REQUIRED: '登录凭据已失效, 请更新凭据后手动重试',
      AUTH_EXPIRED: '登录凭据已失效, 请更新凭据后手动重试',
      INVALID_CREDENTIALS: '登录凭据无效, 请更新凭据后手动重试',
      ACCOUNT_MISMATCH: '返回的账号与配置不一致, 请核对用户 ID 和用户名',
      WAF_CHALLENGE: '站点要求验证. 请在本机处理或更新 Cookie, 本机通过验证不保证服务器可访问',
      ACCESS_BLOCKED: '站点拒绝访问. 请核对站点限制, 不会自动反复尝试',
      RATE_LIMITED: '站点限制请求频率, 请按提示等待后手动重试',
      UNCERTAIN: '请求结果不确定. 请先到站点核对是否已执行, 再决定是否重试',
      REQUEST_UNCERTAIN: '请求结果不确定. 请先到站点核对是否已执行, 再决定是否重试',
      CAPTCHA_REQUIRED: '站点要求验证码. 请在本机处理后更新凭据',
      NETWORK_ERROR: '网络请求失败, 请检查网络和代理配置',
      account_disabled: '账号已停用', ACCOUNT_DISABLED: '账号已停用', ACCOUNT_PAUSED: '账号已暂停, 请处理问题后再手动重试',
      unsupported_account_configuration: '账号配置不受支持, 请重新配置',
      invalid_http_configuration: 'HTTP 配置无效, 请检查超时设置',
      invalid_proxy_configuration: '代理配置无效, 请检查代理设置',
      proxy_authentication_failed: '代理认证失败, 请核对代理 URL 中的用户名和密码',
      proxy_not_configured: '未配置默认代理, 请更新网络设置',
      rate_limited: '站点限制请求频率, 请按提示等待后手动重试',
      response_redirected: '接口返回跳转, 可能需要重新登录或人工验证',
      service_unavailable: '站点服务暂时不可用, 请稍后重试',
      interactive_verification_required: '站点要求验证. 请在本机处理或更新 Cookie, 本机通过验证不保证服务器可访问',
      acw_challenge_unsupported: '站点返回无法识别的 acw 验证格式, 已停止请求. 请在本机处理后更新完整 Cookie',
      acw_cookie_context_missing: '访问验证缺少可用 Cookie 上下文, 已停止请求. 请更新完整 Cookie',
      acw_challenge_limit: 'acw 访问验证达到 3 次请求上限, 已停止请求. 请在本机处理后更新完整 Cookie',
      acw_challenge_requires_confirmation: '请求返回 acw 验证页, 执行结果需要先到站点核对, 核对后再解除暂停',
      html_response_received: '接口返回网页, 请核对站点是否要求登录或验证',
      credentials_rejected: '凭据被站点拒绝, 请更新凭据后手动重试',
      access_blocked: '站点拒绝访问. 请核对站点限制, 不会自动反复尝试',
      request_result_unknown: '请求结果不确定. 请先到站点核对是否已执行, 再决定是否重试',
      network_error: '网络请求失败, 请检查网络和代理配置',
      invalid_json_response: '接口返回无法解析的结果, 写请求请先核对站点记录',
      http_request_rejected: '接口拒绝请求, 请检查账号配置和站点状态',
      user_info_rejected: '用户信息请求被拒绝, 请核对凭据',
      invalid_user_info: '无法核验返回的用户信息, 未继续签到',
      account_identity_mismatch: '返回账号与配置不一致, 请核对用户 ID 和用户名',
      system_token_and_user_id_required: '需要填写系统访问令牌和目标站点用户 ID',
      user_info_requested_reward_unverified: '用户信息请求已完成, 奖励请以站点记录为准',
      session_load_failed: '无法读取加密会话, 请检查服务存储状态',
      invalid_saved_session: '已保存的会话无效, 请更新凭据',
      invalid_cookie_configuration: 'Cookie 格式无效, 请填写完整 Cookie header',
      cookie_user_id_required: 'Cookie 认证需要填写目标站点用户 ID',
      username_and_password_required: '需要填写站点登录账号和密码',
      password_login_rejected: '站点拒绝账号密码登录, 请核对凭据',
      agent_checkin_verified: '登录响应已确认签到, 身份核验通过',
      agent_checkin_not_confirmed: '登录响应未确认签到, 请到站点核对后再决定是否重试',
      agent_checkin_result_unknown: '登录响应缺少有效的签到状态, 请先到站点核对结果',
      login_identity_unverified: '登录接口未返回可核验的用户 ID, 请补充用户 ID 后重试',
      checkin_rejected: '站点拒绝签到请求, 请核对站点状态',
      checkin_verification_failed: '签到请求后未能核验账号结果, 请先到站点核对后再决定是否重试',
      session_save_failed: '操作已执行但加密会话保存失败, 请先核对站点记录',
      already_checked_in: '站点返回今日已签到', checkin_verified: '签到接口已接受, 后续用户信息已核验',
      startup_already_checked_in: '当天已有核验成功记录, 本次启动跳过签到',
      startup_network_unavailable: '启动时网络尚未就绪, 有限等待后仍无法连接, 本次未发送签到请求',
      startup_history_unavailable: '无法核对当天运行记录, 本次启动未发送签到请求',
      REQUEST_CANCELLED_RESULT_UNKNOWN: '任务已停止, 请求结果仍待核对. 请先查看站点记录',
      HTTP_EXECUTION_FAILED_RESULT_UNKNOWN: 'HTTP 执行异常, 请求结果待核对. 请先查看站点记录',
      WORKER_INTERRUPTED_RESULT_UNKNOWN: '执行进程中断, 请求结果待核对. 请先查看站点记录',
      HTTP_EXECUTION_FAILED: 'HTTP 执行失败, 请检查服务日志', HTTP_WORKER_FAILED: '执行进程失败, 请检查服务日志',
    })[code] || code;
  }

  function taskKindLabel(kind) {
    return ({ balance: '余额采集', summary: '每日摘要' })[kind] || '签到任务';
  }

  function renderStatus(data) {
    const run = data.run;
    const currentBadge = badge(run?.state);
    currentBadge.id = 'task-badge';
    $('task-badge').replaceWith(currentBadge);
    $('task-description').textContent = run ? `${taskKindLabel(run.kind)} #${run.id}, ${formatTime(run.started_at)} 开始.${run.error ? ` ${explainError(run.error)}` : ''}${run.state === 'needs_attention' ? run.kind === 'summary' ? ' 摘要发送需要处理, 请查看自动通知记录.' : run.kind === 'balance' ? ' 部分账号余额暂不可用, 请查看查询结果.' : ' 部分账号已暂停, 请查看近期记录并更新凭据.' : ''}${run.state === 'uncertain' ? run.kind === 'summary' ? ' 通知发送结果待确认, 不会自动重发.' : ' 请先在站点核对结果, 避免重复执行.' : ''}` : '还没有运行中的任务. 配置完成后即可开始.';
    setText($('task-progress'), progressText(run?.summary?.progress, run?.state));
    $('next-run').textContent = data.next_run_at ? `下次签到: ${formatBalanceTime(data.next_run_at)}${state.config?.schedule?.mode === 'cron' ? ' / Cron 固定时间' : ''}` : '定时任务未启用, 或尚未安排下一次运行.';
    document.querySelectorAll('[data-next-checkin]').forEach((item) => { item.textContent = $('next-run').textContent; });
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

  function stageLabel(stage) {
    return ({ prepare: '准备账号', load_session: '读取会话', password_login: '账号密码登录', acw_verification: '处理 acw 访问验证', verify_identity: '核验账号', checkin: '发送签到请求', verify_result: '核验签到结果', read_balance: '查询余额', balance: '查询余额', save_balance: '保存余额', save_session: '保存会话', finished: '账号处理结束', notify: '发送通知' })[stage] || stage || '等待执行';
  }

  function requestDetail(item) {
    if (!item || typeof item !== 'object') return '';
    const parts = [];
    if (['GET', 'POST'].includes(item.method)) parts.push(item.method);
    if (typeof item.path === 'string' && /^\/api\/[a-z0-9/_-]+$/i.test(item.path)) parts.push(item.path);
    if (Number.isInteger(item.http_status)) parts.push(`HTTP ${item.http_status}`);
    if (['TimeoutException', 'ConnectTimeout', 'ReadTimeout', 'WriteTimeout', 'PoolTimeout', 'ConnectError', 'ProxyError', 'NetworkError', 'ReadError', 'WriteError', 'CloseError', 'ProtocolError', 'LocalProtocolError', 'RemoteProtocolError', 'RequestError', 'HTTPStatusError', 'UnsupportedProtocol', 'TooManyRedirects', 'DecodingError', 'ExecutionError'].includes(item.error_type)) parts.push(item.error_type);
    if (Number.isFinite(item.timeout_seconds)) parts.push(`超时设置 ${item.timeout_seconds} 秒`);
    if (Number.isInteger(item.request_attempt) && item.request_attempt > 0 && item.request_attempt <= 3 && item.max_attempts === 3) parts.push(`请求 ${item.request_attempt} / ${item.max_attempts}`);
    if (Number.isInteger(item.acw_challenges) && item.acw_challenges > 0 && item.acw_challenges <= 3) parts.push(`acw 验证 ${item.acw_challenges} 次`);
    return parts.join(' / ');
  }

  function progressText(progress, runState) {
    if (!progress || !Number.isInteger(progress.total) || !Number.isInteger(progress.completed)) return '';
    const active = progress.active_account;
    const running = ['running', 'stopping'].includes(runState);
    return `已处理 ${progress.completed} / ${progress.total} 个账号${active ? `. ${running ? '当前' : '最后阶段'}: ${active.name || active.id || '账号'} / ${stageLabel(active.stage)}${requestDetail(active) ? ` / ${requestDetail(active)}` : ''}` : progress.completed < progress.total ? running ? '. 等待下一个账号' : '. 任务已结束, 部分账号未处理' : '. 账号处理完成'}`;
  }

  function setText(item, text) {
    if (item.textContent !== text) item.textContent = text;
    item.hidden = !text;
  }

  function reasonText(reason) {
    if (!reason) return '';
    const explanation = explainError(reason);
    return explanation === reason ? /^[a-z][a-z0-9_]*$/i.test(reason) ? `代码: ${reason}` : String(reason) : `${explanation}. 代码: ${reason}`;
  }

  function createAccountResult() {
    const root = el('section', 'run-account');
    const title = el('p', 'run-account-title');
    const reason = el('p', 'run-meta');
    const verification = el('p', 'run-meta');
    const diagnostic = el('p', 'run-meta run-diagnostic');
    const retry = el('p', 'run-meta');
    const steps = el('ol', 'run-steps');
    root.append(title, reason, verification, diagnostic, retry, steps);
    return { root, title, reason, verification, diagnostic, retry, steps };
  }

  function updateAccountResult(view, account, kind) {
    const outcome = account.pending_outcome || account.outcome || (account.success ? 'succeeded' : 'failed');
    const reason = account.pending_reason || account.reason || account.error;
    const agentVerified = account.provider === 'agentrouter' && account.success && reason === 'agent_checkin_verified';
    setText(view.title, `${account.name || account.id || '账号'}: ${account.pending_outcome ? '已暂停, ' : ''}${kind === 'balance' && account.success ? '余额已更新' : agentVerified ? '签到成功' : runLabel(outcome)}`);
    setText(view.reason, reasonText(reason));
    const verification = account.provider === 'agentrouter' && reason === 'user_info_requested_reward_unverified' ? '历史用户信息请求未验证签到, 请以站点记录为准.' : account.verification_reason ? `结果核验: ${reasonText(account.verification_reason)}` : '';
    setText(view.verification, verification);
    const diagnostic = account.diagnostic;
    setText(view.diagnostic, diagnostic ? `诊断: ${stageLabel(diagnostic.stage)}${requestDetail(diagnostic) ? ` / ${requestDetail(diagnostic)}` : ''}` : '');
    setText(view.retry, Number.isFinite(account.retry_after_seconds) ? `至少等待 ${account.retry_after_seconds} 秒` : '');
    const steps = Array.isArray(account.steps) ? account.steps.filter((step) => step && typeof step === 'object') : [];
    steps.forEach((step, index) => {
      const item = view.steps.children[index] || el('li');
      const next = steps[index + 1];
      const legacyChallenge = step.state === 'failed' && ['password_login', 'verify_identity', 'verify_result'].includes(step.stage) && next?.stage === 'acw_verification' && step.method && step.method === next.method && step.path && step.path === next.path;
      const stepState = legacyChallenge ? 'verification_required' : step.state;
      const status = ({ running: '执行中', completed: '完成', verification_required: '需要访问验证', failed: '失败' })[stepState] || stepState || '';
      setText(item, `${stageLabel(step.stage)}: ${status}${step.at ? ` / ${formatTime(step.at)}` : ''}${requestDetail(step) ? ` / ${requestDetail(step)}` : ''}`);
      item.className = stepState === 'failed' ? 'step-failed' : '';
      if (!item.parentNode) view.steps.append(item);
    });
    while (view.steps.children.length > steps.length) view.steps.lastChild.remove();
    view.steps.hidden = !steps.length;
  }

  function createRunView(run) {
    const root = el('div', 'run-row');
    root.dataset.runId = run.id;
    const main = el('div', 'run-main');
    const title = el('p', 'run-title', `${taskKindLabel(run.kind)} #${run.id}`);
    const started = el('p', 'run-meta');
    const finished = el('p', 'run-meta');
    const error = el('p', 'run-meta run-diagnostic');
    const counts = el('p', 'run-meta');
    const progress = el('p', 'run-progress');
    const notification = el('p', 'run-meta');
    const details = el('details', 'run-details');
    details.append(el('summary', '', '查看账号结果和步骤'));
    const active = el('p', 'run-active run-meta');
    details.append(active);
    main.append(title, started, finished, error, counts, progress, notification, details);
    const status = badge(run.state);
    root.append(main, status);
    return { root, started, finished, error, counts, progress, notification, details, active, status, accounts: new Map() };
  }

  function updateRunView(view, run) {
    const summary = run.summary && typeof run.summary === 'object' ? run.summary : {};
    setText(view.started, formatTime(run.started_at));
    setText(view.finished, run.finished_at ? `结束: ${formatTime(run.finished_at)}` : '');
    setText(view.error, reasonText(run.error));
    setText(view.counts, typeof summary.success_count === 'number' && typeof summary.total_count === 'number' ? `成功 ${summary.success_count} / ${summary.total_count}` : '');
    setText(view.progress, progressText(summary.progress, run.state));
    setText(view.notification, summary.notification_error ? '通知发送异常. 请检查通知配置和服务日志.' : '');
    setText(view.status, runLabel(run.state));
    view.status.className = badge(run.state).className;
    const active = summary.progress?.active_account;
    setText(view.active, active ? `${['running', 'stopping'].includes(run.state) ? '正在处理' : '最后处理'} ${active.name || active.id || '账号'}: ${stageLabel(active.stage)}${active.at ? ` / ${formatTime(active.at)}` : ''}${requestDetail(active) ? ` / ${requestDetail(active)}` : ''}` : '');
    const accounts = Array.isArray(summary.accounts) ? summary.accounts.filter((account) => account && typeof account === 'object') : [];
    const keys = new Set();
    accounts.forEach((account, index) => {
      const key = String(account.id ?? index);
      keys.add(key);
      let result = view.accounts.get(key);
      if (!result) { result = createAccountResult(); view.accounts.set(key, result); }
      updateAccountResult(result, account, run.kind);
      const position = view.details.children[index + 2];
      if (position !== result.root) view.details.insertBefore(result.root, position || null);
    });
    view.accounts.forEach((account, key) => { if (!keys.has(key)) { account.root.remove(); view.accounts.delete(key); } });
    view.details.hidden = !accounts.length && !active;
  }

  async function loadRuns() {
    if (state.runsLoading) return;
    state.runsLoading = true;
    $('refresh-runs').disabled = true;
    try {
      const data = await api('/api/runs');
      const list = $('runs-list');
      const scrollTop = list.scrollTop;
      const runs = data.runs.slice(0, 12);
      const keys = new Set(runs.map((run) => String(run.id)));
      if (!state.runViews.size) list.replaceChildren();
      runs.forEach((run, index) => {
        const key = String(run.id);
        let view = state.runViews.get(key);
        if (!view) { view = createRunView(run); state.runViews.set(key, view); }
        updateRunView(view, run);
        const position = list.children[index];
        if (position !== view.root) list.insertBefore(view.root, position || null);
      });
      state.runViews.forEach((view, key) => { if (!keys.has(key)) { view.root.remove(); state.runViews.delete(key); } });
      if (!runs.length) list.replaceChildren(el('p', 'muted small', '暂无运行记录. 首次执行后会显示在这里.'));
      list.scrollTop = scrollTop;
      $('runs-error').hidden = true;
    } catch (error) {
      $('runs-error').hidden = false;
      $('runs-error').querySelector('span').textContent = `${errorText(error)}${state.runViews.size ? ' 已保留上次读取的记录, 内容可能已过期.' : ''}`;
    } finally {
      state.runsLoading = false;
      $('refresh-runs').disabled = false;
    }
  }

  function renderWorkspaceView() {
    const status = state.view === 'status';
    $('balance-view').hidden = !status;
    $('management-view').hidden = status;
    $('page-eyebrow').textContent = status ? 'ACCOUNT STATUS' : 'OVERVIEW';
    $('page-title').textContent = status ? '账户 Status' : '签到控制台';
    $('page-description').textContent = status ? '余额、每日新增与变化, 在这里查看.' : '先保存配置, 再执行签到. 任务与配置分别管理.';
    document.title = status ? '账户 Status | NewAPI' : 'NewAPI 签到控制台';
    document.querySelectorAll('[data-view]').forEach((item) => {
      if (item.dataset.view === state.view) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
  }

  function switchView(view, push = true) {
    state.view = view === 'status' ? 'status' : 'manage';
    if (push) window.history.pushState(null, '', state.view === 'status' ? '/status' : '/');
    renderWorkspaceView();
    if (state.authenticated && state.view === 'status') Promise.allSettled([loadBalances(), loadAutomation()]);
  }

  function money(value, signed = false) {
    if (typeof value !== 'number' || !Number.isFinite(value)) return '未知';
    const amount = new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 }).format(Math.abs(value));
    return `${value < 0 ? '-' : signed && value > 0 ? '+' : ''}$${amount}`;
  }

  function metric(label, value, hint, signed = false) {
    const root = el('section', 'balance-metric');
    root.append(el('p', 'metric-label', label), el('p', 'metric-value', money(value, signed)), el('p', 'muted small', hint));
    return root;
  }

  function balanceReason(account) {
    const known = {
      balance_updated: '真实余额已核验', balance_verified: '真实余额已核验', balance_refreshed: '真实余额已核验',
      balance_not_collected: '尚无采集数据', balance_collection_failed: '余额采集失败. 已保留上次成功结果.',
      balance_session_required: '暂无可用会话. 请先完成一次正常签到, 或更新 Any Cookie.',
      session_required: '暂无可用会话. 请先完成一次正常签到, 或更新 Any Cookie.',
      balance_session_expired: '监测会话已失效. 请等待下一次正常签到, 或更新 Any Cookie.',
      balance_unavailable: '站点未返回有效余额', invalid_balance: '站点未返回有效余额',
      balance_fields_missing: '站点未返回有效余额', account_disabled: '账号已停用',
    };
    return known[account.reason] || (account.reason ? reasonText(account.reason) : account.updated_at ? '' : '尚无采集数据');
  }

  function balanceState(account) {
    if (!account.enabled || account.state === 'disabled') return '已停用';
    if (account.stale && account.updated_at) return '余额已过期';
    return ({ ok: '已更新', unknown: '暂无数据', needs_credentials: '待更新会话', blocked: '访问受阻', rate_limited: '请求限流', failed: '查询失败' })[account.state] || '暂无数据';
  }

  function duration(since, until = Date.now()) {
    const millis = (value) => typeof value === 'number' ? value < 1e12 ? value * 1000 : value : Date.parse(value);
    const seconds = Math.max(0, Math.floor((millis(until) - millis(since)) / 1000));
    if (!Number.isFinite(seconds)) return '时长未知';
    if (seconds < 60) return `${seconds} 秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分钟`;
    return `${Math.floor(seconds / 86400)} 天 ${Math.floor(seconds % 86400 / 3600)} 小时`;
  }

  function healthText(health, scope) {
    const title = scope === 'checkin' ? '签到' : '余额查询';
    if (!health) return `${title}: 尚无健康记录`;
    const healthy = ['healthy', 'ok', 'success'].includes(health.state);
    const label = healthy ? health.recovered_at ? '已恢复' : '正常' : ({ uncertain: '结果待核对', blocked: '访问受阻', rate_limited: '请求限流', needs_credentials: '待更新凭据', unknown: '尚无记录', disabled: '已停用' })[health.state] || '异常';
    return `${title}: ${label}${!healthy && health.failure_since ? `, 持续 ${duration(health.failure_since)}` : ''}${healthy && health.recovered_at ? ` / 恢复于 ${formatBalanceTime(health.recovered_at)}` : ''}${healthy && health.recovered_at && health.failure_since ? ` / 此前异常 ${duration(health.failure_since, health.recovered_at)}` : ''}${!healthy && health.reason ? ` / ${reasonText(health.reason)}` : ''}`;
  }

  function accountHealth(account) {
    const health = account.health || {};
    const rows = Array.isArray(state.automation?.health) ? state.automation.health : [];
    return ['checkin', 'balance'].map((scope) => healthText(health[scope] || rows.find((item) => item.account_id === account.id && item.scope === scope), scope)).join('\n');
  }

  function renderBalanceAccounts(accounts) {
    const list = $('balance-accounts');
    const keys = new Set();
    if (!state.balanceViews.size) list.replaceChildren();
    accounts.forEach((account, index) => {
      const id = String(account.id);
      keys.add(id);
      let view = state.balanceViews.get(id);
      if (!view) {
        const root = el('article', 'balance-account');
        root.dataset.balanceAccount = id;
        const heading = el('div', 'balance-account-heading');
        const name = el('h3');
        const status = el('span', 'badge');
        const refresh = button('刷新', 'button quiet balance-account-refresh', () => refreshBalances(id));
        refresh.dataset.balanceRefresh = id;
        heading.append(name, status, refresh);
        const provider = el('p', 'muted small');
        const amount = el('p', 'account-balance');
        const changes = el('p', 'balance-changes');
        const source = el('p', 'balance-source muted small');
        const updated = el('p', 'muted small');
        const health = el('p', 'account-health muted small');
        const details = el('details', 'balance-details');
        details.append(el('summary', '', '查看查询详情'));
        const reason = el('p', 'muted small');
        const used = el('p', 'muted small');
        details.append(reason, used);
        root.append(heading, provider, amount, changes, source, updated, health, details);
        view = { root, name, status, refresh, provider, amount, changes, source, updated, health, reason, used };
        state.balanceViews.set(id, view);
      }
      view.name.textContent = account.name || id;
      view.status.textContent = balanceState(account);
      view.status.className = `badge ${account.stale || !['ok', 'disabled'].includes(account.state) ? 'warning' : account.state === 'ok' ? 'success' : ''}`;
      view.refresh.dataset.enabled = String(account.enabled === true);
      view.refresh.setAttribute('aria-label', `刷新余额 ${account.name || id}`);
      view.provider.textContent = account.provider === 'agentrouter' ? 'AgentRouter' : account.provider === 'anyrouter' ? 'AnyRouter' : account.provider || '';
      view.amount.textContent = money(account.balance);
      const incomePartial = account.income_partial ?? account.partial;
      const netPartial = account.net_change_partial ?? account.partial;
      view.changes.textContent = `今日新增 ${money(account.today_income, true)} / ${netPartial ? '采集期净变化' : '净变化'} ${money(account.today_net_change, true)}`;
      const source = ({ site: '站点今日入账', checkin: '仅已核验签到收益', observed: '采集期间已观测入账' })[account.income_source];
      view.source.textContent = `${source ? `新增来源: ${source}` : '新增来源: 暂无可靠数据'}${incomePartial ? '. 新增仅覆盖采集期间, 不代表全天统计.' : ''}${netPartial ? '. 净变化以当日首次采集为基准.' : ''}${account.observed_since ? ` 采集基准: ${formatBalanceTime(account.observed_since)}` : ''}`;
      view.updated.textContent = `最后更新: ${formatBalanceTime(account.updated_at)}${account.stale && account.updated_at ? '. 保留上次已知余额.' : ''}`;
      view.health.textContent = accountHealth(account);
      view.reason.textContent = balanceReason(account) || '查询完成. 余额监测不会自动重新登录.';
      view.used.textContent = `累计已用额度: ${money(account.used)}`;
      const position = list.children[index];
      if (position !== view.root) list.insertBefore(view.root, position || null);
    });
    state.balanceViews.forEach((view, key) => { if (!keys.has(key)) { view.root.remove(); state.balanceViews.delete(key); } });
    if (!accounts.length) list.replaceChildren(el('p', 'muted small', '暂无已连接账户. 请先在管理面板添加并保存账号.'));
  }

  function formatBalanceTime(value) {
    if (!value) return '暂无';
    const date = new Date(typeof value === 'number' && value < 1e12 ? value * 1000 : value);
    if (Number.isNaN(date.getTime())) return '未知';
    return date.toLocaleString('zh-CN', { timeZone: 'Asia/Singapore', hour12: false }).replaceAll('/', '-') + ' UTC+8';
  }

  function renderBalanceHistory(history) {
    const supplied = history.filter((entry) => entry && /^\d{4}-\d{2}-\d{2}$/.test(entry.day) && Number.isFinite(Date.parse(entry.day))).sort((a, b) => a.day.localeCompare(b.day));
    const rows = [];
    if (supplied.length) {
      const byDay = new Map(supplied.map((entry) => [entry.day, entry]));
      const end = Date.parse(supplied[supplied.length - 1].day);
      const start = Math.max(Date.parse(supplied[0].day), end - 29 * 86400000);
      for (let at = start; at <= end; at += 86400000) {
        const day = new Date(at).toISOString().slice(0, 10);
        rows.push(byDay.get(day) || { day, balance: null, today_income: null, today_net_change: null, balance_count: 0 });
      }
    }
    const body = $('balance-history');
    body.replaceChildren();
    rows.slice().reverse().forEach((entry) => {
      const row = el('tr');
      [entry.day, money(entry.balance), money(entry.today_income, true), money(entry.today_net_change, true), `${entry.balance_count ?? 0} 个账号`].forEach((value) => row.append(el('td', '', value)));
      body.append(row);
    });
    const chart = $('balance-chart');
    chart.replaceChildren();
    const known = rows.filter((entry) => typeof entry.balance === 'number' && Number.isFinite(entry.balance));
    if (!known.length) { chart.append(el('p', 'muted small', '尚无趋势数据. 首次成功采集后开始记录.')); return; }
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 900 200');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `最近 ${rows.length} 天余额趋势, ${known.length} 天有数据. 精确数值见下方每日数据.`);
    const min = Math.min(...known.map((entry) => entry.balance));
    const max = Math.max(...known.map((entry) => entry.balance));
    const range = max - min || Math.max(Math.abs(max) * 0.1, 1);
    const x = (index) => 90 + (rows.length === 1 ? 355 : index / (rows.length - 1) * 710);
    const y = (value) => 145 - (value - min) / range * 100;
    const label = (value, px, py, anchor) => {
      const text = document.createElementNS(ns, 'text');
      text.setAttribute('x', px); text.setAttribute('y', py);
      if (anchor) text.setAttribute('text-anchor', anchor);
      text.textContent = value; svg.append(text);
    };
    label(money(max), 5, 40); label(money(min), 5, 150);
    label(rows[0].day, 90, 183); label(rows[rows.length - 1].day, 800, 183, 'end');
    let segment = [];
    const finish = () => {
      if (segment.length > 1) {
        const line = document.createElementNS(ns, 'polyline');
        line.setAttribute('points', segment.join(' ')); line.setAttribute('class', 'balance-chart-line'); svg.append(line);
      }
      segment = [];
    };
    rows.forEach((entry, index) => {
      if (typeof entry.balance !== 'number' || !Number.isFinite(entry.balance)) { finish(); return; }
      const cx = x(index), cy = y(entry.balance);
      segment.push(`${cx},${cy}`);
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', cx); dot.setAttribute('cy', cy); dot.setAttribute('r', '4');
      const title = document.createElementNS(ns, 'title'); title.textContent = `${entry.day}: ${money(entry.balance)}`;
      dot.append(title); svg.append(dot);
    });
    finish(); chart.append(svg);
  }

  function deliveryLabel(value) {
    return ({ accepted: '服务端已接收, 设备送达待确认', sent: '服务端已接收, 设备送达待确认', succeeded: '服务端已接收, 设备送达待确认', partial: '部分渠道已接收, 其余结果请核对', delivered: '渠道已确认送达', failed: '发送失败', failure: '发送失败', unknown: '发送结果待确认, 不自动重发', uncertain: '发送结果待确认, 不自动重发', sending: '正在发送', pending: '等待发送', not_configured: '未配置通知渠道', suppressed: '已按冷却规则合并', skipped: '已跳过' })[value] || value || '状态未知';
  }

  function renderAutomation() {
    const data = state.automation || {};
    const daily = data.daily_summary || {};
    $('daily-summary-status').textContent = `${daily.next_at ? `下次日报: ${formatBalanceTime(daily.next_at)}` : '定时日报尚未安排'}${daily.last_day ? `. 最近日报: ${daily.last_day}${daily.last_state ? ` / ${deliveryLabel(daily.last_state)}` : ''}` : ''}. 时间按 UTC+8 统计.`;
    const list = $('automation-events');
    const expanded = new Set(Array.from(list.querySelectorAll('details[open]')).map((item) => item.dataset.notificationId));
    list.replaceChildren();
    const rows = Array.isArray(data.notifications) ? data.notifications.slice(0, 20) : [];
    rows.forEach((item) => {
      const row = el('article', 'automation-event');
      const title = ({ low_balance: '低余额告警', recovery: '故障恢复通知', daily_summary: '每日摘要', summary: '每日摘要' })[item.kind] || '自动通知';
      row.append(el('p', 'automation-event-title', title), el('p', 'muted small', `${deliveryLabel(item.state)} / ${formatBalanceTime(item.finished_at || item.created_at)}`));
      if (item.reason || item.error) row.append(el('p', 'muted small', reasonText(item.reason || item.error)));
      const channels = Array.isArray(item.delivery?.channels) ? item.delivery.channels : [];
      if (channels.length) {
        const details = el('details', 'automation-delivery-details');
        details.dataset.notificationId = String(item.id);
        details.open = expanded.has(String(item.id));
        details.append(el('summary', '', '查看渠道结果'));
        channels.forEach((channel) => {
          const error = ({ notification_rejected: '渠道拒绝通知', provider_acceptance_unconfirmed: '渠道未确认接收', notification_outcome_unknown: '网络或服务异常, 发送结果待确认' })[channel.error_code] || channel.error_code;
          details.append(el('p', 'muted small', `${channel.channel}: ${deliveryLabel(channel.state)}${error ? ` / ${error}` : ''}`));
        });
        row.append(details);
      }
      list.append(row);
    });
    if (!rows.length) list.append(el('p', 'muted small', '尚无通知记录. 在通知渠道中启用需要的自动提醒.'));
    if (state.balances) renderBalanceAccounts(state.balances.accounts || []);
    updateControls();
  }

  async function loadAutomation() {
    if (state.automationLoading || !state.authenticated) return;
    state.automationLoading = true;
    $('retry-automation').disabled = true;
    try {
      state.automation = await api('/api/automation');
      renderAutomation();
      $('automation-error').hidden = true;
    } catch (error) {
      $('automation-error').hidden = false;
      $('automation-error').querySelector('span').textContent = `自动提醒状态读取失败. ${errorText(error)}${state.automation ? ' 已保留上次读取的记录.' : ''}`;
    } finally {
      state.automationLoading = false;
      $('retry-automation').disabled = false;
    }
  }

  async function sendDailySummary() {
    if (!state.config || state.busy || state.uncertain || state.dirty || !state.statusFresh || state.status?.running) return;
    setBusy(true);
    try {
      await api('/api/automation/summary', { method: 'POST', body: { revision: state.revision } });
      notice('日报发送任务已启动. 请在自动通知记录中确认结果, 服务端接收不代表手机已送达.');
      await Promise.allSettled([loadStatus(), loadRuns(), loadAutomation()]);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain('summary', errorText(error));
      else { notice(errorText(error), error.status === 409 ? 'warning' : 'error'); await loadStatus(); }
    } finally { setBusy(false); }
  }

  function renderBalances(data) {
    const summary = data.summary || {};
    const total = summary.account_count ?? 0;
    $('balance-summary').replaceChildren(
      metric('总余额', summary.balance, `已知 ${summary.balance_count ?? 0} / ${total} 个账号, 含上次已知值`),
      metric('今日新增', summary.today_income, `覆盖 ${summary.income_count ?? 0} / ${total} 个账号, 不扣消费`, true),
      metric('今日净变化', summary.today_net_change, `覆盖 ${summary.net_change_count ?? 0} / ${total} 个账号, 按采集基准计算, 包含消费`, true),
      (() => { const root = el('section', 'balance-metric'); root.append(el('p', 'metric-label', '有效采集'), el('p', 'metric-value', `${summary.fresh_count ?? 0} / ${total}`), el('p', 'muted small', '过期与缺失数据请查看账户详情')); return root; })(),
    );
    $('balance-day').textContent = data.day ? `${data.day} / UTC+8` : 'UTC+8';
    const interval = state.config?.monitoring?.interval_minutes ?? 60;
    $('balance-refresh-hint').textContent = data.refreshing ? '正在串行采集账户余额. 不会自动登录或执行签到.' : `${data.next_refresh_at ? `下次采集: ${formatBalanceTime(data.next_refresh_at)}.` : '自动采集未安排.'} 采集间隔 ${interval} 分钟, 可在管理面板调整. 重新读取只读取缓存.`;
    renderBalanceAccounts(Array.isArray(data.accounts) ? data.accounts : []);
    renderBalanceHistory(Array.isArray(data.history) ? data.history : []);
    updateControls();
  }

  async function loadBalances() {
    if (state.balancesLoading || !state.authenticated) return;
    state.balancesLoading = true;
    $('read-balances').disabled = true;
    $('retry-balances').disabled = true;
    try {
      const data = await api('/api/balances');
      state.balances = data;
      renderBalances(data);
      $('balances-error').hidden = true;
    } catch (error) {
      $('balances-error').hidden = false;
      $('balances-error').querySelector('span').textContent = `余额读取失败. ${errorText(error)}${state.balances ? ' 已保留上次结果, 数据可能已过期.' : ''}`;
    } finally {
      state.balancesLoading = false;
      $('read-balances').disabled = false;
      $('retry-balances').disabled = false;
      updateControls();
    }
  }

  async function refreshBalances(accountId = null) {
    if (!state.config || state.busy || state.uncertain || state.dirty || !state.statusFresh || state.status?.running || state.balances?.refreshing) return;
    setBusy(true);
    try {
      const body = { revision: state.revision };
      if (accountId) body.account_id = accountId;
      await api('/api/balances/refresh', { method: 'POST', body });
      notice('余额采集任务已启动. 仅查询已保存会话, 不会自动登录或执行签到.');
      await Promise.allSettled([loadStatus(), loadRuns(), loadBalances()]);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain('balance', errorText(error));
      else { notice(errorText(error), error.status === 409 ? 'warning' : 'error'); await loadStatus(); }
    } finally { setBusy(false); }
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
    try { await Promise.allSettled([loadStatus(), loadRuns(), ...(state.view === 'status' ? [loadBalances(), loadAutomation()] : [])]); }
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
    await Promise.allSettled([loadRuns(), ...(state.uncertain === 'summary' ? [loadAutomation()] : [])]);
    if (success && state.uncertain !== 'config') {
      const resolving = state.uncertain === 'resolve';
      const remainsPaused = resolving && state.status?.attention?.[state.resolveAccount];
      state.uncertain = null;
      state.resolveAccount = null;
      notice(resolving ? remainsPaused ? '已重新读取状态, 此账号仍然暂停. 请先核对站点结果, 再决定是否解除暂停.' : '已重新读取状态, 此账号当前没有暂停记录. 本次没有执行签到.' : '已重新读取任务状态. 请核对当前任务和近期记录后再操作.');
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
    if (options.type === 'number') input.step = options.step || '1';
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

  function moveExpanded(oldKey, newKey) {
    if (state.expanded.has(oldKey)) {
      state.expanded.set(newKey, state.expanded.get(oldKey));
      state.expanded.delete(oldKey);
    }
  }

  function card(title, index, remove, options) {
    const outer = el('section', 'config-card');
    const head = el('div', 'card-heading');
    const toggle = button('', 'card-toggle', () => {
      state.expanded.set(options.key(), !state.expanded.get(options.key()));
      applyExpanded();
    });
    const text = el('span', 'card-copy');
    const name = el('span', 'card-title');
    const summary = el('span', 'card-summary');
    const affordance = el('span', 'card-affordance');
    text.append(name, summary);
    toggle.append(el('span', 'card-index', String(index + 1).padStart(2, '0')), text, affordance);
    const content = el('div', 'card-content');
    content.id = `card-content-${++card.counter}`;
    toggle.setAttribute('aria-controls', content.id);
    const applyExpanded = () => {
      const open = !!state.expanded.get(options.key());
      toggle.setAttribute('aria-expanded', String(open));
      content.hidden = !open;
      outer.classList.toggle('collapsed', !open);
      affordance.textContent = open ? '收起' : '展开';
    };
    if (!state.expanded.has(options.key())) state.expanded.set(options.key(), !options.saved);
    applyExpanded();
    const refresh = () => { name.textContent = title(); summary.textContent = options.summary(); };
    refresh();
    state.cardHeaders.push(refresh);
    const removeButton = button('移除', 'text-button remove', remove);
    removeButton.setAttribute('aria-label', `移除${title()}`);
    head.append(toggle, removeButton);
    const grid = el('div', 'form-grid');
    content.append(grid);
    outer.append(head, content);
    return { outer, grid, content };
  }
  card.counter = 0;

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

  function resetAccountAuth(account, type, changedSite = false) {
    for (const key of ['cookies', 'username', 'password', 'system_access_token']) delete account[key];
    if (changedSite) { delete account.api_user; delete account.expected_username; }
    account.auth_type = type;
  }

  function renderAccounts(container) {
    container.append(heading('签到账号', '第一版仅支持 anyrouter.top 和 agentrouter.org. 凭据在服务器加密保存, 保存不会执行登录或签到.', '+ 添加账号', () => {
      const account = { id: uniqueKey('account', state.config.accounts.map((item) => item.id)), name: '', provider: 'anyrouter', auth_type: 'cookie', enabled: true };
      state.config.accounts.push(account);
      markDirty(); renderForm();
    }));
    const cards = el('div', 'cards');
    if (!state.config.accounts.length) empty(cards, '添加第一个账号', 'AnyRouter 支持 Cookie 或站点账号密码. AgentRouter 仅支持站点账号密码.');
    state.config.accounts.forEach((account, index) => {
      const { outer, grid, content } = card(() => account.name || account.id || '新账号', index, () => { state.expanded.delete(`account:${account.id}`); state.config.accounts.splice(index, 1); markDirty(); renderForm(); }, {
        key: () => `account:${account.id}`, saved: state.savedIds.has(account.id),
        summary: () => `${account.provider === 'agentrouter' ? 'agentrouter.org' : 'anyrouter.top'} / ${({ cookie: 'Cookie', password: '站点账号密码' })[account.auth_type] || '待重新配置'} / ${account.enabled ? '已启用' : '已停用'}`,
      });
      outer.dataset.accountId = account.id;
      const runAccount = button('签到此账号', 'button secondary account-run', () => taskAction(false, account.id));
      runAccount.dataset.accountRun = account.id;
      runAccount.setAttribute('aria-label', `签到账号 ${account.name || account.id || '新账号'}`);
      const head = outer.querySelector('.card-heading');
      head.insertBefore(runAccount, head.lastChild);
      grid.append(
        field('账号名称', account.name, (value) => { account.name = value; }, { placeholder: '例如: 主账号', optional: true }),
        selectField('目标站点', account.provider, [['anyrouter', 'AnyRouter - anyrouter.top'], ['agentrouter', 'AgentRouter - agentrouter.org']], (value) => {
          account.provider = value;
          resetAccountAuth(account, value === 'agentrouter' ? 'password' : 'cookie', true);
          renderForm();
        }, { hint: '切换站点会移除当前草稿中不兼容的凭据, 保存后才会应用.' }),
        field('稳定 ID', account.id, (value) => { moveExpanded(`account:${account.id}`, `account:${value}`); account.id = value; }, { required: true, readOnly: state.savedIds.has(account.id), hint: '首次保存后固定, 不随名称变化.' }),
        checkField('启用此账号', account.enabled, (value) => { account.enabled = value; }, '停用时可先保留未完成的配置, 不参与签到.'),
        selectField('认证方式', account.auth_type, account.provider === 'agentrouter' ? [['password', '站点账号密码']] : [['cookie', '已有 Cookie'], ['password', '站点账号密码']], (value) => { resetAccountAuth(account, value); renderForm(); }),
      );
      if (account.auth_type === 'password') {
        const agent = account.provider === 'agentrouter';
        grid.append(field('站点登录账号', account.username, (value) => { account.username = value; }, { autocomplete: 'off', hint: agent ? '填写 AgentRouter 的站点用户名或邮箱.' : '填写 AnyRouter 的用户名或邮箱.' }));
        grid.append(secretField('站点密码', account.password, (value) => { account.password = value; }, { hint: agent ? '每次签到重新登录 AgentRouter, 不复用登录会话. 仅确认站点返回已签到才显示签到成功. 登录后的会话仅供后续只读余额监测.' : '已知 acw 访问验证可自动处理, 其他验证码或未知验证会暂停并通知, 请在本机处理后更新凭据.' }));
      } else if (account.auth_type === 'cookie' && account.provider === 'anyrouter') {
        const cookie = secretField('Cookie', account.cookies, (value) => { account.cookies = value; }, { wide: true, placeholder: 'session=...; other=...', hint: '输入完整 Cookie header. 已保存值留空保留, 点击清除才删除.' });
        cookie.append(el('p', 'field-hint', '先登录 https://anyrouter.top, 按 F12 -> Application -> Cookies -> https://anyrouter.top, 找到 session 并复制其 Value, 在上方手动粘贴 session=复制的值. 也可从 Network 的 Request Headers 复制包含 session 的完整 Cookie 值. acw_sc__v2 只是访问验证 Cookie, 不能替代登录 Cookie.'));
        grid.append(cookie);
      }
      grid.append(
        field('目标站点用户 ID', account.api_user, (value) => { account.api_user = value; }, { optional: account.auth_type === 'password', placeholder: '例如: 12345', hint: 'Cookie 认证必须填写站点用户 ID. 账号密码认证可选填, 用于核对登录账号.' }),
        field('目标站点用户名', account.expected_username, (value) => { account.expected_username = value; }, { optional: true, hint: '可额外核对服务器返回的用户名, 不匹配时暂停.' }),
      );
      content.append(advanced('账号代理', [proxyField('代理', account, 'proxy', '沿用上级时使用默认代理; 默认代理未配置时直连. 支持 HTTP/HTTPS 和 SOCKS5, 认证格式: socks5://用户名:密码@主机:端口. 特殊字符需进行 URL 编码.')]));
      content.append(advanced('账号告警', [field('低余额阈值, 站内美元额度', account.low_balance_threshold, (value) => { account.low_balance_threshold = value; }, { type: 'number', min: 0, max: 1e12, step: 'any', optional: true, hint: '留空沿用通知设置中的全局阈值. 仅在低余额告警启用且本次采集成功时判断, 未知或过期余额不触发.' })]));
      const attention = el('div', 'hint-box');
      attention.dataset.accountAttention = account.id;
      attention.hidden = true;
      const attentionMessage = el('p', 'small');
      attentionMessage.dataset.attentionMessage = '';
      const resolve = button('已核对结果, 解除暂停', 'button secondary', () => resolveAccountAttention(account.id));
      resolve.dataset.accountResolve = account.id;
      resolve.hidden = true;
      attention.append(attentionMessage, resolve);
      content.append(attention);
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
    container.append(heading('通知渠道', '填写需要启用的渠道, 留空则不发送. 通知可能在执行签到或需要更新凭据时发出, 保存不会发送测试通知.'));
    const automation = state.config.automation;
    const settings = el('section', 'automation-settings');
    settings.append(el('h3', '', '自动提醒'));
    const grid = el('div', 'form-grid');
    grid.append(
      checkField('启用低余额告警', automation.low_balance.enabled, (value) => { automation.low_balance.enabled = value; }, '仅对已启用账户的成功、新鲜余额判断. 未知、过期或停用账户不触发.'),
      field('全局低余额阈值', automation.low_balance.threshold, (value) => { automation.low_balance.threshold = value; }, { type: 'number', min: 0, max: 1e12, step: 'any', required: true, hint: '站内美元额度. 单账户可在账号详情中的账号告警里覆盖此值.' }),
      field('低余额提醒冷却, 分钟', automation.low_balance.cooldown_minutes, (value) => { automation.low_balance.cooldown_minutes = value; }, { type: 'number', min: 1, max: 10080, required: true, hint: '持续低余额时按冷却间隔提醒, 回升后重新判断. 重启服务会保留通知状态.' }),
      checkField('启用故障恢复通知', automation.recovery.enabled, (value) => { automation.recovery.enabled = value; }, '账号在记录真实故障后恢复成功时通知. 签到与余额查询分别判断, 首次成功不会误报恢复.'),
      field('恢复提醒冷却, 分钟', automation.recovery.cooldown_minutes, (value) => { automation.recovery.cooldown_minutes = value; }, { type: 'number', min: 1, max: 10080, required: true, hint: '同一账户频繁异常与恢复时合并提醒, 健康状态仍持续记录.' }),
      checkField('启用每日日报', automation.daily_summary.enabled, (value) => { automation.daily_summary.enabled = value; }, '每日发送签到结果、余额、新增额度与异常账户摘要. 数据缺失或仅覆盖观察期时会标明.'),
      field('每日日报时间, UTC+8', automation.daily_summary.time, (value) => { automation.daily_summary.time = value; }, { type: 'time', required: true, hint: '按 Asia/Singapore 时区执行. 日报读取已有记录, 不额外登录或签到.' }),
    );
    settings.append(grid);
    const action = el('button', 'button secondary', '发送今日日报');
    action.type = 'button';
    action.dataset.sendSummary = '';
    const actions = el('div', 'automation-settings-actions');
    actions.append(action, el('p', 'field-hint', '点击后会通过已配置的渠道真实发送. 保存配置本身不发送通知; 结果不确定时不会自动重发.'));
    settings.append(actions);
    container.append(settings);
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
    container.append(heading('定时与网络', '定时任务由当前服务调度, 服务停止期间不会补跑. 固定时间与日报均按 UTC+8 执行.'));
    if (state.runtime?.runtime === 'go') container.append(localRuntimePanel());
    const schedule = state.config.schedule;
    const scheduling = el('section', 'runtime-group');
    scheduling.append(el('h3', '', '运行计划'));
    const scheduleGrid = el('div', 'form-grid');
    scheduleGrid.append(
      checkField('启用定时签到', schedule.enabled, (value) => { schedule.enabled = value; }, '保存后生效. 同一时间只运行一个任务, 需要处理的账号会暂停自动执行.'),
      selectField('签到计划方式', schedule.mode, [['interval', '按间隔执行'], ['cron', 'Cron 固定时间']], (value) => { schedule.mode = value; renderForm(); }, { hint: '按间隔执行沿用原有计划; Cron 使用固定的 UTC+8 时间.' }),
    );
    if (schedule.mode === 'cron') {
      scheduleGrid.append(field('Cron 表达式', schedule.cron, (value) => { schedule.cron = value; }, { required: true, wide: true, placeholder: '0 8 * * *', hint: '标准 5 字段: 分 时 日 月 星期. 支持 *、列表、范围和步长, 最短间隔 30 分钟. 星期 0 或 7 代表周日.' }));
      const presets = el('div', 'cron-presets field-wide');
      [['每天 08:00', '0 8 * * *'], ['每天 08:00 和 20:00', '0 8,20 * * *'], ['每周一 08:00', '0 8 * * 1']].forEach(([label, value]) => presets.append(button(label, 'button quiet', () => { schedule.cron = value; markDirty(); renderForm(); })));
      scheduleGrid.append(presets);
    } else scheduleGrid.append(field('运行间隔, 分钟', schedule.interval_minutes, (value) => { schedule.interval_minutes = value; }, { type: 'number', min: 30, max: 10080, required: true, hint: '允许 30 至 10080 分钟. 请根据站点规则设置合理间隔.' }));
    scheduling.append(scheduleGrid);
    const next = el('p', 'hint-box', state.status?.next_run_at ? `下次签到: ${formatBalanceTime(state.status.next_run_at)}` : '定时任务未启用, 或尚未安排下一次运行.');
    next.dataset.nextCheckin = '';
    scheduling.append(next);
    const monitoring = state.config.monitoring;
    const monitoringGroup = el('section', 'runtime-group');
    monitoringGroup.append(el('h3', '', '余额监测'));
    const monitoringGrid = el('div', 'form-grid');
    monitoringGrid.append(
      checkField('启用定时余额采集', monitoring.enabled, (value) => { monitoring.enabled = value; }, '仅使用已有会话查询余额, 会话失效时等待正常签到或更新凭据. 不会自动重新登录.'),
      field('余额采集间隔, 分钟', monitoring.interval_minutes, (value) => { monitoring.interval_minutes = value; }, { type: 'number', min: 30, max: 10080, required: true, hint: '默认 60 分钟. 与签到任务串行执行, 页面刷新只读取已保存数据.' }),
    );
    monitoringGroup.append(monitoringGrid);
    const network = el('section', 'runtime-group'); network.append(el('h3', '', 'HTTP 与通知入口'));
    const networkGrid = el('div', 'form-grid');
    networkGrid.append(
      field('HTTP 超时, 秒', state.config.http.timeout_seconds, (value) => { state.config.http.timeout_seconds = value; }, { type: 'number', min: 5, max: 120, required: true, hint: '请求超时不代表签到失败. 写请求结果不确定时请先核对站点记录.' }),
      field('WebUI 地址', state.config.webui_url, (value) => { state.config.webui_url = value; }, { type: 'url', optional: true, placeholder: 'https://checkin.example.com', hint: '可选. 通知中的配置入口, 不含密码或令牌. 仅填写你能私有访问的管理地址.' }),
    );
    network.append(networkGrid);
    const proxy = el('section', 'runtime-group'); proxy.append(el('h3', '', '默认代理'));
    proxy.append(secretField('代理 URL', state.config.proxy_url, (value) => { state.config.proxy_url = value; }, { placeholder: 'socks5://用户名:密码@主机:1080', hint: '支持 HTTP/HTTPS 和 SOCKS5. 认证格式: socks5://用户名:密码@主机:端口. 用户名和密码中的 @ : / # % 等特殊字符需进行 URL 编码. 供沿用上级或使用默认代理的账号使用. 已保存值留空保留, 点击清除才删除.' }));
    container.append(scheduling, monitoringGroup, network, proxy);
  }

  async function loadLocalRuntime() {
    if (state.backend !== 'go') return;
    try {
      const result = await api('/api/runtime');
      if (result.runtime === 'go') { state.runtime = result; if (state.tab === 'runtime' && !state.dirty) renderForm(); }
    } catch (_) { /* The Python edition has no local lifecycle endpoint. */ }
  }

  function localRuntimePanel() {
    const panel = el('section', 'runtime-group go-runtime-panel');
    panel.append(el('h3', '', '本机启动与后台运行'));
    panel.append(el('p', 'muted small', state.runtime.desktop ? '桌面版关闭窗口后隐藏到托盘, 签到和监测继续运行. 以下设置单独保存, 无需保存账号配置.' : 'Go 独立应用在后台运行, 关闭浏览器不会退出程序. 以下设置单独保存, 无需保存账号配置.'));
    const grid = el('div', 'form-grid');
    const startup = el('label', 'check-field');
    const enabled = document.createElement('input'); enabled.type = 'checkbox'; enabled.id = 'runtime-startup-checkin'; enabled.checked = state.runtime.settings.run_on_startup;
    startup.append(enabled, el('span', '', '启动时自动签到'));
    const delayLabel = el('label', 'field'); delayLabel.append(el('span', 'field-label', '启动等待时间, 秒'));
    const delay = document.createElement('input'); delay.type = 'number'; delay.id = 'runtime-startup-delay'; delay.min = '0'; delay.max = '300'; delay.value = state.runtime.settings.startup_delay_seconds;
    delayLabel.append(delay, el('span', 'field-hint', '等待 0 至 300 秒后启动. 当天已确认成功的账号跳过, 暂停和限流规则继续生效.'));
    grid.append(startup, delayLabel); panel.append(grid);
    const status = el('p', 'inline-message'); status.setAttribute('role', 'status');
    const actions = el('div', 'task-actions');
    const save = button('保存启动设置', 'button secondary', async () => {
      const seconds = Number(delay.value);
      if (!Number.isInteger(seconds) || seconds < 0 || seconds > 300) { status.textContent = '启动等待时间需要为 0 至 300 秒.'; return; }
      await perform(async () => {
        state.runtime = await api('/api/runtime', { method: 'PUT', body: { revision: state.runtime.settings.revision, run_on_startup: enabled.checked, startup_delay_seconds: seconds } });
        status.textContent = '启动设置已保存, 下次启动生效.';
      });
    }); save.id = 'runtime-save'; actions.append(save);
    const reload = button('重新读取启动设置', 'button quiet', () => perform(async () => {
      state.runtime = await api('/api/runtime'); enabled.checked = state.runtime.settings.run_on_startup; delay.value = state.runtime.settings.startup_delay_seconds; status.textContent = '已重新读取启动设置.';
    })); reload.id = 'runtime-reload'; actions.append(reload);
    if (state.runtime.can_manage_autostart) {
      const autostart = button(state.runtime.autostart_enabled ? '关闭登录后自启' : '启用登录后自启', 'button quiet', async () => {
        if (state.runtime.autostart_enabled && !window.confirm('关闭当前用户的登录后自启? 当前程序会继续运行.')) return;
        await perform(async () => { state.runtime = await api('/api/runtime/autostart', { method: 'POST', body: { enabled: !state.runtime.autostart_enabled } }); autostart.textContent = state.runtime.autostart_enabled ? '关闭登录后自启' : '启用登录后自启'; status.textContent = '登录后自启设置已更新.'; });
      }); autostart.id = 'runtime-autostart'; actions.append(autostart);
    }
    if (state.runtime.can_shutdown) {
      const exit = button('退出后台程序', 'button danger-soft', async () => {
        if (!window.confirm('退出将停止当前任务和后续定时任务. 是否退出后台程序?')) return;
        await perform(async () => { await api('/api/runtime/shutdown', { method: 'POST', body: {} }); stopPolling(); status.textContent = '程序正在退出. 下次可重新启动应用.'; });
      }); exit.id = 'runtime-exit'; actions.append(exit);
    }
    async function perform(action) {
      if (state.runtimeBusy) return; state.runtimeBusy = true;
      actions.querySelectorAll('button').forEach((item) => { item.disabled = true; });
      try { await action(); }
      catch (error) { status.textContent = `${errorText(error)} 请重新读取后确认设置.`; }
      finally { state.runtimeBusy = false; actions.querySelectorAll('button').forEach((item) => { item.disabled = false; }); }
    }
    panel.append(actions, status, el('p', 'field-hint', '登录后自启只适用于当前用户. 无需登录即可运行时, 请使用命令行安装系统服务. 系统服务的安装和卸载需要管理员权限.'));
    return panel;
  }

  const renderers = { accounts: renderAccounts, notifications: renderNotifications, runtime: renderRuntime };

  function renderForm() {
    if (!state.config) return;
    state.cardHeaders = [];
    const container = $('form-content'); container.replaceChildren();
    renderers[state.tab](container);
    document.querySelectorAll('[data-tab]').forEach((item) => {
      item.classList.toggle('active', item.dataset.tab === state.tab);
      if (item.dataset.tab === state.tab) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    });
    updateControls();
  }

  function validateDraft(config) {
    const ids = new Set();
    for (const account of config.accounts) {
      if (typeof account.id !== 'string' || !account.id || account.id.length > 128 || account.id.trim() !== account.id) return '账号稳定 ID 不能为空, 不能包含首尾空白, 且不能超过 128 个字符.';
      if (ids.has(account.id)) return `账号稳定 ID 重复: ${account.id}`;
      ids.add(account.id);
      const name = account.name || account.id;
      if (!['anyrouter', 'agentrouter'].includes(account.provider)) return `账号 ${name} 的站点不受支持.`;
      if (account.provider === 'agentrouter' ? account.auth_type !== 'password' : !['cookie', 'password'].includes(account.auth_type)) return `账号 ${name} 的认证方式不受此站点支持.`;
      if (account.low_balance_threshold !== null && account.low_balance_threshold !== undefined && (typeof account.low_balance_threshold !== 'number' || !Number.isFinite(account.low_balance_threshold) || account.low_balance_threshold < 0 || account.low_balance_threshold > 1e12)) return `账号 ${name} 的低余额阈值需要为 0 至 1000000000000 的数值, 或留空继承全局阈值.`;
      if (!account.enabled) continue;
      if (account.auth_type === 'password') {
        if (!account.username || !account.password) return `账号 ${name} 需要填写站点登录账号和密码.`;
      } else {
        if (!account.cookies) return `账号 ${name} 需要填写Cookie.`;
        if (account.auth_type === 'cookie' && typeof account.cookies === 'string' && account.cookies !== SECRET && !account.cookies.split(';').some((part) => part.trim().startsWith('session=') && part.trim().slice(8).trim())) return `账号 ${name} 的 Cookie 缺少非空 session. acw_sc__v2 只是访问验证 Cookie, 请按 Cookie 输入框下方说明获取登录 Cookie.`;
        if (!account.api_user || !/^\d+$/.test(String(account.api_user)) || Number(account.api_user) < 1) return `账号 ${name} 需要填写有效的目标站点用户 ID.`;
      }
      if (account.proxy === 'default' && !config.proxy_url) return `账号 ${name} 选择了默认代理, 请先配置代理 URL.`;
    }
    for (const [value, min, max, label] of [[config.schedule.interval_minutes, 30, 10080, '运行间隔'], [config.monitoring.interval_minutes, 30, 10080, '余额采集间隔'], [config.http.timeout_seconds, 5, 120, 'HTTP 超时']]) {
      if (!Number.isInteger(value) || value < min || value > max) return `${label} 需要为 ${min} 至 ${max} 之间的整数.`;
    }
    if (!['interval', 'cron'].includes(config.schedule.mode)) return '请选择有效的签到计划方式.';
    if (config.schedule.mode === 'cron' && (typeof config.schedule.cron !== 'string' || config.schedule.cron.trim().split(/\s+/).length !== 5 || !/^[0-9*,/\s-]+$/.test(config.schedule.cron))) return 'Cron 表达式需要包含 5 个字段, 例如每天 08:00 使用 0 8 * * *.';
    const automation = config.automation;
    if (typeof automation.low_balance.threshold !== 'number' || !Number.isFinite(automation.low_balance.threshold) || automation.low_balance.threshold < 0 || automation.low_balance.threshold > 1e12) return '全局低余额阈值需要为 0 至 1000000000000 的数值.';
    for (const [value, label] of [[automation.low_balance.cooldown_minutes, '低余额提醒冷却'], [automation.recovery.cooldown_minutes, '恢复提醒冷却']]) {
      if (!Number.isInteger(value) || value < 1 || value > 10080) return `${label}需要为 1 至 10080 之间的整数分钟.`;
    }
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(automation.daily_summary.time)) return '每日日报时间需要为有效的 24 小时时间, 例如 23:55.';
    if (config.webui_url) {
      try {
        const url = new URL(config.webui_url);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error();
      } catch (_) { return 'WebUI 地址必须是有效的 HTTP(S) 地址, 不包含凭据, 查询参数或片段.'; }
    }
    return '';
  }

  function prepareConfigForSave() {
    const config = copy(state.config);
    config.accounts.forEach((account) => {
      for (const key of ['name', 'api_user', 'expected_username', 'proxy']) if (account[key] === '') delete account[key];
    });
    return config;
  }

  async function saveConfig(event) {
    event.preventDefault();
    if (!state.config || !state.dirty || state.busy || state.uncertain) return;
    const config = prepareConfigForSave();
    const problem = validateDraft(config);
    if (problem) { notice(problem, 'error'); return; }
    setBusy(true);
    try {
      const data = await api('/api/config', { method: 'PUT', body: { config, revision: state.revision } });
      state.config = normalizeConfig(data.config);
      state.revision = data.revision;
      state.savedIds = new Set(state.config.accounts.map((account) => account.id));
      state.dirty = false;
      renderForm();
      notice('配置已保存. 本次保存没有执行登录或签到.');
      await loadStatus();
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain('config', errorText(error));
      else if (error.status === 409) notice(`保存冲突, 当前草稿已保留. ${errorText(error)} 请重新读取前先保留所需修改.`, 'warning');
      else notice(errorText(error), 'error');
    } finally { setBusy(false); }
  }

  async function taskAction(stop, accountId = null) {
    if (state.busy || state.uncertain || !state.statusFresh || !state.authenticated) return;
    if (!stop && (!state.config || state.configLoading)) return;
    if (!stop && state.dirty) { notice('请先保存当前修改, 再启动任务.', 'warning'); return; }
    if (!stop && state.status?.running) return;
    if (!stop && accountId && accountRunBlocked(accountId)) return;
    setBusy(true);
    try {
      const path = stop ? '/api/runs/stop' : '/api/runs';
      const body = stop ? {} : { revision: state.revision };
      if (!stop && accountId) body.account_id = accountId;
      await api(path, { method: 'POST', body });
      notice(stop ? '已请求停止任务. 请等待运行状态更新.' : accountId ? '此账号的签到任务已启动. 可在当前任务和近期运行中查看进度及结果.' : '签到任务已启动. 结果不确定或仍在限流期限内的账号继续暂停, 请查看近期记录.');
      await Promise.allSettled([loadStatus(), loadRuns()]);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain(stop ? 'stop' : 'run', errorText(error));
      else { notice(errorText(error), error.status === 409 ? 'warning' : 'error'); await loadStatus(); }
    } finally { setBusy(false); }
  }

  async function resolveAccountAttention(accountId) {
    if (!state.config || state.busy || state.uncertain || state.dirty || !state.statusFresh || state.status?.running || !state.savedIds.has(accountId) || state.status?.attention?.[accountId]?.outcome !== 'uncertain') return;
    if (!window.confirm('上次写请求可能已经完成. 请先到目标站点核对签到和奖励记录. 确认已经核对结果后解除暂停? 本次只解除暂停, 不会立即执行签到.')) return;
    setBusy(true);
    state.resolveAccount = accountId;
    try {
      await api('/api/accounts/resolve', { method: 'POST', body: { account_id: accountId, revision: state.revision } });
      state.resolveAccount = null;
      notice('已解除此账号的暂停. 本次没有执行签到, 如需重试请手动开始.');
      await Promise.allSettled([loadStatus(), loadRuns()]);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500 || error.status === 0 || (error.status >= 200 && error.status < 300)) setUncertain('resolve', errorText(error));
      else {
        state.resolveAccount = null;
        notice(errorText(error), error.status === 409 ? 'warning' : 'error');
        await loadStatus();
      }
    } finally { setBusy(false); }
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if ($('login-button').disabled || state.loginBusy) return;
    state.loginBusy = true;
    renderLoginPolicy();
    $('login-message').textContent = '正在登录...';
    $('login-message').className = 'inline-message';
    try {
      if (state.authPolicy.setup_required) {
        await api('/api/setup', { method: 'POST', body: { password: $('login-password').value, confirm_password: $('login-confirm-password').value } });
        renderLoginPolicy(await api('/api/session'));
      }
      await enterWorkspace(await api('/api/login', { method: 'POST', body: { password: $('login-password').value } }));
    }
    catch (error) {
      $('login-message').textContent = errorText(error);
      $('login-message').className = 'inline-message error';
    } finally { state.loginBusy = false; renderLoginPolicy(); }
  });

  $('passkey-login-button').addEventListener('click', async () => {
    if (state.loginBusy || $('passkey-login-button').disabled) return;
    state.loginBusy = true; renderLoginPolicy();
    $('login-message').textContent = '请在浏览器或设备上完成 Passkey 验证...';
    $('login-message').className = 'inline-message';
    try { await enterWorkspace(await window.CheckinPasskeys.login(api)); }
    catch (error) { $('login-message').textContent = window.CheckinPasskeys.errorMessage(error); $('login-message').className = 'inline-message error'; }
    finally { state.loginBusy = false; renderLoginPolicy(); }
  });

  $('logout-button').addEventListener('click', async () => {
    if (state.dirty && !window.confirm('退出会丢弃未保存的修改. 是否继续?')) return;
    setBusy(true);
    try {
      await api('/api/logout', { method: 'POST', body: {} });
      state.config = null; state.revision = null; state.dirty = false; state.uncertain = null;
      $('form-content').replaceChildren();
      $('runs-list').replaceChildren();
      state.runViews.clear();
      state.balances = null;
      state.automation = null;
      state.balanceViews.clear();
      $('balance-accounts').replaceChildren();
      $('balance-summary').replaceChildren();
      $('balance-history').replaceChildren();
      $('balance-chart').replaceChildren();
      $('automation-events').replaceChildren();
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
  document.querySelectorAll('[data-view]').forEach((item) => item.addEventListener('click', (event) => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    switchView(item.dataset.view);
  }));
  window.addEventListener('popstate', () => switchView(window.location.pathname === '/status' ? 'status' : 'manage', false));
  $('read-balances').addEventListener('click', loadBalances);
  $('retry-balances').addEventListener('click', loadBalances);
  $('retry-automation').addEventListener('click', loadAutomation);
  document.addEventListener('click', (event) => {
    const target = event.target.closest('[data-send-summary]');
    if (target && !target.disabled) sendDailySummary();
  });
  $('refresh-balances').addEventListener('click', () => refreshBalances());
  $('config-form').addEventListener('submit', saveConfig);
  $('reload-config').addEventListener('click', () => loadConfig(true));
  $('retry-config').addEventListener('click', () => loadConfig(false));
  $('retry-status').addEventListener('click', loadStatus);
  $('refresh-runs').addEventListener('click', loadRuns);
  $('retry-runs').addEventListener('click', loadRuns);
  $('start-button').addEventListener('click', () => taskAction(false));
  $('stop-button').addEventListener('click', () => taskAction(true));
  window.addEventListener('beforeunload', (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stopPolling(); else if (state.authenticated) poll(); });

  async function boot() {
    $('login-button').disabled = true;
    try {
      const session = await api('/api/session');
      renderLoginPolicy(session);
      if (session.authenticated) await enterWorkspace(session);
      else showLogin('');
    } catch (error) { showLogin(errorText(error)); }
  }
  boot();
})();
