(() => {
    'use strict';

    function resolveHandler(name) {
        const handler = name
            .split('.')
            .reduce((value, part) => value && value[part], window);
        return typeof handler === 'function' ? handler : null;
    }

    function parseArguments(element) {
        if (!element.dataset.cspArgs) {
            return [];
        }
        try {
            const args = JSON.parse(element.dataset.cspArgs);
            return Array.isArray(args) ? args : [];
        } catch (error) {
            console.error('Argumentos CSP inválidos', error);
            return [];
        }
    }

    function invokeHandlers(element, attribute, event) {
        const names = (element.dataset[attribute] || '')
            .split(',')
            .map((name) => name.trim())
            .filter(Boolean);
        const configuredArgs = parseArguments(element);

        names.forEach((name) => {
            const handler = resolveHandler(name);
            if (!handler) {
                console.error(`Handler CSP no encontrado: ${name}`);
                return;
            }

            const args = [...configuredArgs];
            if (element.dataset.cspPass === 'event') {
                args.unshift(event);
            } else if (element.dataset.cspPass === 'element-first') {
                args.unshift(element);
            } else if (element.dataset.cspPass === 'element') {
                args.push(element);
            }
            handler.apply(window, args);
        });
    }

    document.addEventListener('click', (event) => {
        const confirmButton = event.target.closest(
            '[data-confirm-submit][data-submit-target]'
        );
        if (confirmButton) {
            event.preventDefault();
            if (window.confirm(confirmButton.dataset.confirmSubmit)) {
                const form = document.getElementById(
                    confirmButton.dataset.submitTarget
                );
                if (form) {
                    form.requestSubmit();
                }
            }
            return;
        }

        const element = event.target.closest('[data-csp-click]');
        if (!element) {
            return;
        }
        if (element.matches('a[href="#"]') || element.dataset.cspPrevent === 'true') {
            event.preventDefault();
        }
        invokeHandlers(element, 'cspClick', event);
    });

    document.addEventListener('change', (event) => {
        const element = event.target.closest('[data-csp-change]');
        if (element) {
            invokeHandlers(element, 'cspChange', event);
        }

        const submitter = event.target.closest('[data-submit-form-on-change]');
        if (submitter && submitter.form) {
            submitter.form.requestSubmit();
        }
    });

    document.addEventListener('blur', (event) => {
        const element = event.target.closest('[data-csp-blur]');
        if (element) {
            invokeHandlers(element, 'cspBlur', event);
        }
    }, true);

    document.addEventListener('input', (event) => {
        const element = event.target.closest('[data-input-filter]');
        if (!element) {
            return;
        }
        if (element.dataset.inputFilter === 'digits-hyphen') {
            element.value = element.value.replace(/[^0-9-]/g, '');
        } else if (element.dataset.inputFilter === 'no-digits') {
            element.value = element.value.replace(/[0-9]/g, '');
        } else if (element.dataset.inputFilter === 'decimal') {
            element.value = element.value.replace(/[^0-9.]/g, '');
        }
    });

    document.addEventListener('submit', (event) => {
        const form = event.target.closest('form[data-confirm-submit]');
        if (
            form
            && !window.confirm(form.dataset.confirmSubmit)
        ) {
            event.preventDefault();
        }
    });
})();
