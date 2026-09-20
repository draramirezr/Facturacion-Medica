(() => {
    'use strict';

    const idiomas = new Set(['es', 'en', 'fr']);

    function idiomaActivo() {
        const valor = (document.documentElement.lang || 'es').toLowerCase();
        return idiomas.has(valor) ? valor : 'es';
    }

    function correctorActivo() {
        return document.body.getAttribute('spellcheck') !== 'false';
    }

    function esCampoDeTexto(element) {
        if (!element || element.nodeType !== 1) {
            return false;
        }
        const tag = element.tagName;
        if (tag === 'TEXTAREA') {
            return true;
        }
        if (tag !== 'INPUT') {
            return false;
        }
        const tipo = (element.getAttribute('type') || 'text').toLowerCase();
        return [
            'text', 'search', 'url', 'tel', '',
        ].includes(tipo);
    }

    function aplicarCampo(element) {
        if (!esCampoDeTexto(element) || element.closest('[data-no-spellcheck]')) {
            return;
        }
        const activo = correctorActivo();
        element.setAttribute('spellcheck', activo ? 'true' : 'false');
        if (activo) {
            element.setAttribute('lang', idiomaActivo());
        }
    }

    function aplicarDocumento(raiz) {
        const origen = raiz && raiz.querySelectorAll ? raiz : document;
        if (esCampoDeTexto(origen)) {
            aplicarCampo(origen);
        }
        origen.querySelectorAll('input, textarea').forEach(aplicarCampo);
    }

    document.addEventListener('DOMContentLoaded', () => {
        if (document.documentElement.lang === 'none') {
            document.documentElement.lang = 'es';
        }
        aplicarDocumento(document);
        new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((nodo) => {
                    if (nodo.nodeType === 1) {
                        aplicarDocumento(nodo);
                    }
                });
            });
        }).observe(document.body, { childList: true, subtree: true });
    });
})();
