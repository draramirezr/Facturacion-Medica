(() => {
    const DEBOUNCE_MS = 400;

    function esFormularioGet(form) {
        return (form.getAttribute('method') || 'get').toLowerCase() === 'get';
    }

    function enviarFiltro(form) {
        if (!form || form.dataset.autoFiltroPaused === '1') return;
        if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return;
        }
        form.submit();
    }

    function vincularCampoTexto(form, el) {
        if (el.closest('[data-patient-directory-search]') || el.closest('[data-patient-search]')) {
            el.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    enviarFiltro(form);
                }
            });
            return;
        }

        let timer;
        const programar = () => {
            if (el.disabled) return;
            clearTimeout(timer);
            timer = setTimeout(() => enviarFiltro(form), DEBOUNCE_MS);
        };
        el.addEventListener('input', programar);
        el.addEventListener('search', programar);
        el.addEventListener('change', programar);
    }

    function vincularFormulario(form) {
        if (!esFormularioGet(form) || form.dataset.noAutoFiltro === '1') return;
        if (form.dataset.autoFiltroBound === '1') return;
        form.dataset.autoFiltroBound = '1';

        form.querySelectorAll('select, input[type="date"], input[type="datetime-local"], input[type="month"], input[type="week"]').forEach((el) => {
            el.addEventListener('change', () => enviarFiltro(form));
        });

        form.querySelectorAll('input[type="checkbox"]').forEach((el) => {
            if (el.hasAttribute('data-select-all')) return;
            el.addEventListener('change', () => enviarFiltro(form));
        });

        form.querySelectorAll('input[type="text"], input[type="search"], textarea').forEach((el) => {
            vincularCampoTexto(form, el);
        });
    }

    function init() {
        document.querySelectorAll('form').forEach(vincularFormulario);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
