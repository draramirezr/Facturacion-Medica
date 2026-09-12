(function () {
    'use strict';

    const meta = document.querySelector('meta[name="csrf-token"]');
    const token = meta ? meta.getAttribute('content') : '';
    if (!token) {
        return;
    }

    const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

    function addTokenToForm(form) {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (!unsafeMethods.has(method) || form.querySelector('input[name="csrf_token"]')) {
            return;
        }
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = token;
        form.appendChild(input);
    }

    document.querySelectorAll('form').forEach(addTokenToForm);
    document.addEventListener('submit', function (event) {
        if (event.target instanceof HTMLFormElement) {
            addTokenToForm(event.target);
        }
    }, true);

    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
        const options = Object.assign({}, init || {});
        const requestMethod = input instanceof Request ? input.method : 'GET';
        const method = (options.method || requestMethod).toUpperCase();
        const requestUrl = input instanceof Request ? input.url : String(input);
        const url = new URL(requestUrl, window.location.href);

        if (url.origin === window.location.origin && unsafeMethods.has(method)) {
            const sourceHeaders = options.headers
                || (input instanceof Request ? input.headers : undefined);
            const headers = new Headers(sourceHeaders || {});
            if (!headers.has('X-CSRFToken')) {
                headers.set('X-CSRFToken', token);
            }
            options.headers = headers;
        }

        return originalFetch.call(window, input, options);
    };
})();
