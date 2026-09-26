(function () {
    'use strict';

    const storageKey = 'arsflow-color-mode';
    const root = document.documentElement;

    function preferredMode() {
        try {
            const saved = window.localStorage.getItem(storageKey);
            if (saved === 'light' || saved === 'dark') return saved;
        } catch (error) {
            // La preferencia seguirá funcionando durante la sesión.
        }
        return window.matchMedia?.('(prefers-color-scheme: dark)').matches
            ? 'dark'
            : 'light';
    }

    function updateButtons(mode) {
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            const dark = mode === 'dark';
            button.setAttribute('aria-label', dark ? 'Activar modo claro' : 'Activar modo oscuro');
            button.setAttribute('title', dark ? 'Modo claro' : 'Modo oscuro');
            button.setAttribute('aria-pressed', String(dark));
            const icon = button.querySelector('[data-theme-icon]');
            if (icon) icon.className = dark ? 'fas fa-sun' : 'fas fa-moon';
            const label = button.querySelector('[data-theme-label]');
            if (label) label.textContent = dark ? 'Modo claro' : 'Modo oscuro';
        });
        document.querySelectorAll('input[name="modo_color"]').forEach((input) => {
            input.checked = input.value === mode;
        });
    }

    function persistAccount(mode) {
        if (root.dataset.colorAccount !== '1') {
            return;
        }
        const body = JSON.stringify({ modo: mode });
        window.fetch('/perfil/modo-color', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body,
            credentials: 'same-origin',
        }).catch(() => {
            // El modo visual ya cambió; se reintentará en el próximo clic.
        });
    }

    function setMode(mode, persist) {
        const nextMode = mode === 'dark' ? 'dark' : 'light';
        root.dataset.colorMode = nextMode;
        updateButtons(nextMode);
        if (persist) {
            try {
                window.localStorage.setItem(storageKey, nextMode);
            } catch (error) {
                // El selector visual sigue funcionando aunque storage esté bloqueado.
            }
            persistAccount(nextMode);
        }
    }

    function initialize() {
        if (root.dataset.colorAccount === '1' && root.dataset.colorMode) {
            setMode(root.dataset.colorMode, false);
        } else {
            setMode(root.dataset.colorMode || preferredMode(), false);
        }
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            button.addEventListener('click', () => {
                setMode(root.dataset.colorMode === 'dark' ? 'light' : 'dark', true);
            });
        });
        document.querySelectorAll('input[name="modo_color"]').forEach((input) => {
            input.addEventListener('change', () => {
                if (input.checked) setMode(input.value, true);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
