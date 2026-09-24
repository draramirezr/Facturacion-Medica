(function () {
    'use strict';

    const config = window.ClinicRDCola;
    if (!config || !config.estadoUrl) {
        return;
    }

    const claveIds = 'clinicrd-cola-ids';
    const claveAviso = 'clinicrd-cola-aviso';
    let firma = config.firmaInicial;
    let avisoMostrado = false;

    const pintarAviso = (texto) => {
        if (avisoMostrado || !texto) {
            return;
        }
        avisoMostrado = true;
        const bar = document.createElement('div');
        bar.setAttribute('role', 'status');
        bar.style.cssText = [
            'margin:0.85rem 0 0',
            'padding:0.75rem 1rem',
            'border-radius:12px',
            'background:#ecfeff',
            'color:#0e7490',
            'font-weight:700',
        ].join(';');
        bar.textContent = texto;
        const hero = document.querySelector('.doctor-hero');
        if (hero && hero.parentNode) {
            hero.parentNode.insertBefore(bar, hero.nextSibling);
        }
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.value = 880;
            gain.gain.value = 0.04;
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.18);
        } catch (error) {
            /* silencio si el navegador bloquea audio */
        }
    };

    const consultar = async () => {
        const respuesta = await fetch(config.estadoUrl, {
            headers: { Accept: 'application/json' },
            credentials: 'same-origin',
        });
        if (!respuesta.ok) {
            return;
        }
        const datos = await respuesta.json();
        const idsPrevios = JSON.parse(sessionStorage.getItem(claveIds) || '[]');
        const idsNuevos = datos.cola_ids || [];
        const llegoAlguien = idsNuevos.some((id) => idsPrevios.indexOf(id) === -1)
            && idsPrevios.length > 0;
        sessionStorage.setItem(claveIds, JSON.stringify(idsNuevos));
        if (llegoAlguien) {
            sessionStorage.setItem(claveAviso, '1');
        }
        if (firma && datos.firma && datos.firma !== firma) {
            window.location.reload();
            return;
        }
        firma = datos.firma || firma;
    };

    if (sessionStorage.getItem(claveAviso) === '1') {
        sessionStorage.removeItem(claveAviso);
        pintarAviso('Llegó un paciente a tu cola.');
    }

    consultar().catch(() => {});
    window.setInterval(() => {
        consultar().catch(() => {});
    }, 8000);
})();
