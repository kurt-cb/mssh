(function () {
  'use strict';

  // Lazy-load the util — base.html includes it before this file via
  // an inline script tag in the register.html scripts block.
  const utilScript = document.createElement('script');
  utilScript.src = '/static/webauthn-util.js';
  utilScript.onload = init;
  document.head.appendChild(utilScript);

  function init() {
    const data = JSON.parse(document.getElementById('ceremony-data').textContent);
    const btn = document.getElementById('register-btn');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      window.mwa.showStatus('secondary', 'Touch your authenticator…');

      let opts;
      try {
        opts = JSON.parse(data.options_json);
        opts = window.mwa.decodeOptions(opts);
      } catch (e) {
        window.mwa.showStatus('danger', 'Bad options payload: ' + e.message);
        btn.disabled = false;
        return;
      }

      let cred;
      try {
        cred = await navigator.credentials.create({publicKey: opts});
      } catch (e) {
        window.mwa.showStatus('danger',
          'Could not complete registration: ' + (e.message || e.name));
        btn.disabled = false;
        return;
      }

      const body = window.mwa.encodeCredential(cred);
      const resp = await fetch(
        '/register/' + encodeURIComponent(data.ceremony_id) + '/respond',
        {method: 'POST',
         headers: {'Content-Type': 'application/json'},
         body: JSON.stringify(body)});
      if (resp.ok) {
        btn.classList.replace('btn-primary', 'btn-outline-secondary');
        btn.textContent = 'Submitted';
        window.mwa.showStatus('success',
          'Credential submitted. Your operator will confirm enrollment.');
      } else {
        const j = await resp.json().catch(() => ({}));
        window.mwa.showStatus('danger',
          'Server refused: ' + (j.reason || resp.status));
        btn.disabled = false;
      }
    });
  }
})();
