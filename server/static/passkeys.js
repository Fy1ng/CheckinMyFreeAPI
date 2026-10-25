'use strict';

(() => {
  function supported() {
    return window.isSecureContext && typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create && !!navigator.credentials?.get;
  }

  function decode(value) {
    if (typeof value !== 'string') throw new Error('Passkey 参数格式无效, 请重新读取页面.');
    const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  }

  function encode(value) {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let raw = '';
    for (const byte of bytes) raw += String.fromCharCode(byte);
    return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  }

  function options(value, registration = false) {
    if (!value || typeof value !== 'object') throw new Error('Passkey 参数缺失, 请重新读取页面.');
    const result = { ...value, challenge: decode(value.challenge) };
    if (registration) result.user = { ...value.user, id: decode(value.user.id) };
    for (const name of ['allowCredentials', 'excludeCredentials']) {
      if (Array.isArray(value[name])) result[name] = value[name].map((entry) => ({ ...entry, id: decode(entry.id) }));
    }
    return result;
  }

  function credentialJSON(credential) {
    if (!credential || credential.type !== 'public-key') throw new Error('未取得 Passkey 验证结果.');
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    const response = credential.response;
    const result = {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: encode(response.clientDataJSON) },
      clientExtensionResults: credential.getClientExtensionResults?.() || {},
    };
    if (credential.authenticatorAttachment) result.authenticatorAttachment = credential.authenticatorAttachment;
    if (response.attestationObject) {
      result.response.attestationObject = encode(response.attestationObject);
      if (typeof response.getTransports === 'function') result.response.transports = response.getTransports();
    } else {
      result.response.authenticatorData = encode(response.authenticatorData);
      result.response.signature = encode(response.signature);
      result.response.userHandle = response.userHandle == null ? null : encode(response.userHandle);
    }
    return result;
  }

  function errorMessage(error) {
    if (error?.name === 'NotAllowedError' || error?.name === 'AbortError') return 'Passkey 操作已取消或未完成. 可由你再次点击重试.';
    if (error?.name === 'InvalidStateError') return '此设备可能已保存该 Passkey. 请使用已有密钥验证, 或选择其他认证器.';
    if (error?.name === 'SecurityError') return '当前地址不能使用此 Passkey. 请打开配置的 HTTPS 管理入口, 或通过 SSH 恢复登录设置.';
    if (error?.name === 'NotSupportedError') return '当前浏览器或认证器不支持所需的 Passkey 验证. 请更换浏览器或安全密钥.';
    return typeof error?.message === 'string' && error.message ? error.message : 'Passkey 验证未完成, 请重新读取状态后再试.';
  }

  function requireSupport() {
    if (!supported()) throw new Error('此浏览器或当前地址不支持 Passkey. 请使用支持 WebAuthn 的浏览器和 HTTPS 管理入口.');
  }

  async function assertion(api, prefix) {
    requireSupport();
    const challenge = await api(prefix + '/options', { method: 'POST', body: {} });
    const credential = await navigator.credentials.get({ publicKey: options(challenge.publicKey) });
    return api(prefix + '/verify', { method: 'POST', body: { ticket: challenge.ticket, credential: credentialJSON(credential) } });
  }

  async function login(api) {
    return assertion(api, '/api/passkey/login');
  }

  async function reauth(api) {
    const result = await assertion(api, '/api/security/reauth');
    if (!result.reauth_token) throw new Error('未取得有效的重新验证凭据, 请重试验证.');
    return result.reauth_token;
  }

  async function register(api, label, reauthToken) {
    requireSupport();
    const challenge = await api('/api/security/register/options', { method: 'POST', body: { label, reauth_token: reauthToken } });
    const credential = await navigator.credentials.create({ publicKey: options(challenge.publicKey, true) });
    return api('/api/security/register/verify', { method: 'POST', body: { ticket: challenge.ticket, credential: credentialJSON(credential) } });
  }

  window.CheckinPasskeys = Object.freeze({ supported, errorMessage, login, reauth, register });
})();
