// Base64url ↔ Uint8Array helpers + status renderer for the
// WebAuthn ceremonies. The options_json the broker hands the
// browser has base64url-encoded binary fields (challenge,
// credential IDs, etc.) — WebAuthn's JS API wants ArrayBuffers,
// so we decode on the way in and encode on the way out.

(function () {
  'use strict';

  function b64uToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Walk an options object from JSON and convert known binary
  // fields to ArrayBuffer in place. WebAuthn's API spec says the
  // following are BufferSource: challenge, user.id, excludeCredentials[].id,
  // allowCredentials[].id.
  function decodeOptions(opts) {
    if (opts.challenge && typeof opts.challenge === 'string') {
      opts.challenge = b64uToBytes(opts.challenge);
    }
    if (opts.user && typeof opts.user.id === 'string') {
      opts.user.id = b64uToBytes(opts.user.id);
    }
    const lists = [opts.excludeCredentials, opts.allowCredentials];
    for (const list of lists) {
      if (!list) continue;
      for (const c of list) {
        if (typeof c.id === 'string') c.id = b64uToBytes(c.id);
      }
    }
    return opts;
  }

  // Encode a PublicKeyCredential (the response from create() or
  // get()) back to a plain JSON-able object with base64url fields
  // for binary blobs. Server / back-end client expects this shape.
  function encodeCredential(cred) {
    const out = {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cred.getClientExtensionResults
        ? cred.getClientExtensionResults() : {},
      response: {},
    };
    const r = cred.response;
    if (r.clientDataJSON) {
      out.response.clientDataJSON = bytesToB64u(r.clientDataJSON);
    }
    if (r.attestationObject) {                 // create()
      out.response.attestationObject = bytesToB64u(r.attestationObject);
      if (r.getTransports) {
        out.response.transports = r.getTransports();
      }
    }
    if (r.authenticatorData) {                 // get()
      out.response.authenticatorData = bytesToB64u(r.authenticatorData);
    }
    if (r.signature) {
      out.response.signature = bytesToB64u(r.signature);
    }
    if (r.userHandle) {
      out.response.userHandle = bytesToB64u(r.userHandle);
    }
    return out;
  }

  function showStatus(cls, msg) {
    const el = document.getElementById('status');
    if (!el) return;
    el.innerHTML = '<div class="text-' + cls + '">' + msg + '</div>';
  }

  // Export.
  window.mwa = {
    decodeOptions, encodeCredential, showStatus,
  };
})();
