(function () {
  'use strict';

  const utilScript = document.createElement('script');
  utilScript.src = '/static/webauthn-util.js';
  utilScript.onload = init;
  document.head.appendChild(utilScript);

  function init() {
    const data = JSON.parse(document.getElementById('ceremony-data').textContent);
    const approveBtn = document.getElementById('approve-btn');
    const denyBtn = document.getElementById('deny-btn');

    approveBtn.addEventListener('click', async () => {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      window.mwa.showStatus('secondary', 'Touch your authenticator…');

      let opts;
      try {
        opts = JSON.parse(data.options_json);
        opts = window.mwa.decodeOptions(opts);
      } catch (e) {
        window.mwa.showStatus('danger', 'Bad options payload: ' + e.message);
        approveBtn.disabled = false; denyBtn.disabled = false;
        return;
      }

      let cred;
      try {
        cred = await navigator.credentials.get({publicKey: opts});
      } catch (e) {
        window.mwa.showStatus('danger',
          'Could not complete approval: ' + (e.message || e.name));
        approveBtn.disabled = false; denyBtn.disabled = false;
        return;
      }

      const body = window.mwa.encodeCredential(cred);
      const resp = await fetch(
        '/approve/' + encodeURIComponent(data.ceremony_id) + '/respond',
        {method: 'POST',
         headers: {'Content-Type': 'application/json'},
         body: JSON.stringify(body)});
      if (resp.ok) {
        approveBtn.classList.replace('btn-success', 'btn-outline-secondary');
        approveBtn.textContent = 'Approved';
        denyBtn.style.display = 'none';
        window.mwa.showStatus('success',
          'Approval submitted. The operation will continue.');
      } else {
        const j = await resp.json().catch(() => ({}));
        window.mwa.showStatus('danger',
          'Server refused: ' + (j.reason || resp.status));
        approveBtn.disabled = false; denyBtn.disabled = false;
      }
    });

    denyBtn.addEventListener('click', async () => {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      const resp = await fetch(
        '/approve/' + encodeURIComponent(data.ceremony_id) + '/deny',
        {method: 'POST'});
      if (resp.ok) {
        denyBtn.classList.replace('btn-outline-danger', 'btn-outline-secondary');
        denyBtn.textContent = 'Denied';
        approveBtn.style.display = 'none';
        window.mwa.showStatus('secondary',
          'Operation denied. The operator has been notified.');
      } else {
        approveBtn.disabled = false; denyBtn.disabled = false;
      }
    });
  }
})();
