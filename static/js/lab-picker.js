(() => {
    'use strict';

    const splitList = (value) =>
        String(value || '')
            .split(/\n|;/)
            .map((item) => item.trim())
            .filter(Boolean);

    const uniquePush = (items, name) => {
        const clave = name.trim().toLowerCase();
        if (!clave || items.some((item) => item.toLowerCase() === clave)) {
            return items;
        }
        return [...items, name.trim()];
    };

    const bindPicker = (root) => {
        const searchUrl = root.dataset.searchUrl;
        const chips = root.querySelector('[data-lab-chips]');
        const suggest = root.querySelector('[data-lab-suggest]');
        const list = root.querySelector('[data-lab-list]');
        const input = root.querySelector('#labSearch');
        const manual = root.querySelector('[data-lab-manual]');
        if (!searchUrl || !chips || !suggest || !list || !input) {
            return;
        }

        let items = splitList(list.value);
        let timer = 0;

        const sync = () => {
            list.value = items.join('\n');
            chips.replaceChildren();
            items.forEach((name, index) => {
                const chip = document.createElement('span');
                chip.className = 'lab-chip';
                chip.append(document.createTextNode(name + ' '));
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.setAttribute('aria-label', 'Quitar');
                remove.textContent = '×';
                remove.addEventListener('click', () => {
                    items = items.filter((_, current) => current !== index);
                    sync();
                });
                chip.append(remove);
                chips.append(chip);
            });
        };

        const hideSuggest = () => {
            suggest.classList.add('d-none');
            suggest.replaceChildren();
        };

        const addName = (name) => {
            items = uniquePush(items, name);
            input.value = '';
            hideSuggest();
            sync();
            input.focus();
        };

        const search = () => {
            const query = input.value.trim();
            if (query.length < 1) {
                hideSuggest();
                return;
            }
            const url = `${searchUrl}?q=${encodeURIComponent(query)}`;
            fetch(url, { headers: { Accept: 'application/json' } })
                .then((response) => (response.ok ? response.json() : { pruebas: [] }))
                .then((data) => {
                    const pruebas = data.pruebas || [];
                    suggest.replaceChildren();
                    if (!pruebas.length) {
                        hideSuggest();
                        return;
                    }
                    pruebas.forEach((nombre) => {
                        const option = document.createElement('button');
                        option.type = 'button';
                        option.textContent = nombre;
                        option.addEventListener('click', () => addName(nombre));
                        const row = document.createElement('li');
                        row.append(option);
                        suggest.append(row);
                    });
                    suggest.classList.remove('d-none');
                })
                .catch(() => hideSuggest());
        };

        input.addEventListener('input', () => {
            window.clearTimeout(timer);
            timer = window.setTimeout(search, 180);
        });
        if (manual) {
            manual.addEventListener('click', () => {
                const texto = input.value.trim();
                if (texto) {
                    addName(texto);
                }
            });
        }
        input.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                const first = suggest.querySelector('button');
                if (first && !suggest.classList.contains('d-none')) {
                    first.click();
                    return;
                }
                if (input.value.trim()) {
                    addName(input.value.trim());
                }
            }
        });
        sync();
    };

    document.querySelectorAll('[data-lab-picker]').forEach(bindPicker);
})();
