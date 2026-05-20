// mssh-admin web — minimal vanilla JS for sortable + expandable
// tables and the cert-export action buttons.

(function () {
    'use strict';

    // ---- Row expansion -------------------------------------------------
    document.querySelectorAll('tr.row-expand').forEach((row) => {
        row.addEventListener('click', (ev) => {
            // Don't toggle when clicking action buttons inside the row.
            if (ev.target.closest('button')) return;
            const target = document.querySelector(row.dataset.target);
            if (!target) return;
            const showing = target.style.display !== 'none';
            target.style.display = showing ? 'none' : '';
            row.classList.toggle('expanded', !showing);
            row.querySelector('.chevron').textContent = showing ? '▸' : '▾';
        });
    });

    // ---- Column sort ---------------------------------------------------
    document.querySelectorAll('table.sortable').forEach((table) => {
        const ths = table.querySelectorAll('th[data-sort]');
        ths.forEach((th, colIndex) => {
            th.addEventListener('click', () => {
                // The clicked column is at `colIndex` in the data-sort
                // header; but the visible <th> includes a leading
                // empty <th> for the chevron — so the table column is
                // colIndex + 1.
                const tbody = table.querySelector('tbody');
                // Pairs: (expand-row, detail-row). We sort the
                // expand-rows; the detail-row stays attached just after.
                const allRows = Array.from(tbody.children);
                const pairs = [];
                for (let i = 0; i < allRows.length; i++) {
                    const r = allRows[i];
                    if (r.classList.contains('row-expand')) {
                        const detail = allRows[i + 1];
                        pairs.push([r, detail && detail.classList.contains('row-detail') ? detail : null]);
                    }
                }
                const asc = !th.classList.contains('sorted-asc');
                ths.forEach((x) => x.classList.remove('sorted-asc', 'sorted-desc'));
                th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
                const realCol = colIndex + 1;
                pairs.sort((a, b) => {
                    const av = (a[0].children[realCol].textContent || '').trim();
                    const bv = (b[0].children[realCol].textContent || '').trim();
                    const an = parseFloat(av);
                    const bn = parseFloat(bv);
                    let cmp;
                    if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== '' && bv !== '') {
                        cmp = an - bn;
                    } else {
                        cmp = av.localeCompare(bv);
                    }
                    return asc ? cmp : -cmp;
                });
                // Re-append in new order.
                pairs.forEach(([r, d]) => {
                    tbody.appendChild(r);
                    if (d) tbody.appendChild(d);
                });
            });
        });
    });

    // ---- Cert-export actions ------------------------------------------
    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
    }

    document.querySelectorAll('.server-mtls-export').forEach((btn) => {
        btn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const name = btn.dataset.server;
            if (!confirm(`Re-issue mTLS for ${name}?\n\n` +
                         `The old keypair stops working immediately. ` +
                         `Push the new tarball to /etc/mssh/wrapper-mtls.* ` +
                         `and restart msshd on that host.`)) return;
            btn.disabled = true;
            btn.textContent = 'Re-issuing…';
            try {
                const resp = await fetch(`/api/server/${encodeURIComponent(name)}/mtls`, {method: 'POST'});
                if (!resp.ok) {
                    const body = await resp.text();
                    alert(`Re-issue failed (${resp.status}):\n${body}`);
                    return;
                }
                const blob = await resp.blob();
                downloadBlob(blob, `${name}-mtls.tar`);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Re-issue mTLS…';
            }
        });
    });

    document.querySelectorAll('.user-pki-export').forEach((btn) => {
        btn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const user = btn.dataset.user;
            btn.disabled = true;
            btn.textContent = 'Minting…';
            try {
                const resp = await fetch(`/api/user/${encodeURIComponent(user)}/pki`, {method: 'POST'});
                if (resp.status === 501) {
                    const body = await resp.json();
                    alert(`Not implemented yet:\n\n${body.detail}`);
                    return;
                }
                if (!resp.ok) {
                    const body = await resp.text();
                    alert(`Mint failed (${resp.status}):\n${body}`);
                    return;
                }
                const blob = await resp.blob();
                downloadBlob(blob, `${user}-pki.tar`);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Export PKI…';
            }
        });
    });
})();
