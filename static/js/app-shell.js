(function () {
    'use strict';

    function initAppShell() {
        const sidebar = document.getElementById('arsSidebar');
        const overlay = document.getElementById('arsSidebarOverlay');
        const toggle = document.getElementById('arsSidebarToggle');
        const searchInput = document.getElementById('arsModuleSearch');
        const searchResults = document.getElementById('arsSearchResults');

        if (!sidebar) {
            return;
        }

        document.querySelectorAll('[data-digits-only]').forEach((input) => {
            const maxLength = Number.parseInt(input.dataset.digitsOnly, 10);

            input.addEventListener('input', () => {
                const digits = input.value.replace(/\D/g, '');
                input.value = Number.isFinite(maxLength)
                    ? digits.slice(0, maxLength)
                    : digits;
            });
        });

        const phoneInputs = Array.from(document.querySelectorAll(
            'input[name*="telefono" i], input[id*="telefono" i]'
        ));
        const activePhoneChecks = new WeakMap();

        const verifyPhone = (input) => {
            const digits = input.value.replace(/\D/g, '');
            if (digits.length !== 10 || input.dataset.verifiedPhone === digits) {
                return Promise.resolve(true);
            }
            if (activePhoneChecks.has(input)) {
                return activePhoneChecks.get(input);
            }

            const check = fetch(`/api/verificar-telefono?telefono=${encodeURIComponent(digits)}`, {
                headers: { Accept: 'application/json' }
            })
                .then((response) => {
                    if (!response.ok) {
                        throw new Error('No se pudo verificar el teléfono');
                    }
                    return response.json();
                })
                .then((data) => {
                    const currentPath = window.location.pathname.replace(/\/$/, '');
                    const matches = (data.coincidencias || []).filter(
                        (match) => (match.url || '').replace(/\/$/, '') !== currentPath
                    );
                    if (!matches.length) {
                        input.dataset.verifiedPhone = digits;
                        return true;
                    }

                    const first = matches[0];
                    const additional = matches.length > 1
                        ? `\nTambién aparece en ${matches.length - 1} registro(s) adicional(es).`
                        : '';
                    const proceed = window.confirm(
                        `El número ${digits} está registrado con el ${first.tipo} ` +
                        `"${first.nombre}".${additional}\n\n¿Desea continuar de todos modos?`
                    );
                    if (proceed) {
                        input.dataset.verifiedPhone = digits;
                        return true;
                    }
                    input.value = '';
                    input.focus();
                    return false;
                })
                .catch(() => true)
                .finally(() => activePhoneChecks.delete(input));

            activePhoneChecks.set(input, check);
            return check;
        };

        phoneInputs.forEach((input) => {
            input.addEventListener('input', () => {
                delete input.dataset.verifiedPhone;
            });
            input.addEventListener('blur', () => {
                verifyPhone(input);
            });
        });

        new Set(phoneInputs.map((input) => input.form).filter(Boolean)).forEach((form) => {
            form.addEventListener('submit', async (event) => {
                if (form.dataset.phoneCheckBypass === 'true') {
                    delete form.dataset.phoneCheckBypass;
                    return;
                }

                const formPhones = phoneInputs.filter((input) => input.form === form);
                const pending = formPhones.filter((input) => {
                    const digits = input.value.replace(/\D/g, '');
                    return digits.length === 10 && input.dataset.verifiedPhone !== digits;
                });
                if (!pending.length) {
                    return;
                }

                event.preventDefault();
                const accepted = await Promise.all(pending.map(verifyPhone));
                if (accepted.every(Boolean)) {
                    form.dataset.phoneCheckBypass = 'true';
                    form.requestSubmit(event.submitter || undefined);
                }
            });
        });

        const closeSidebar = () => {
            sidebar.classList.remove('open');
            overlay?.classList.remove('show');
            toggle?.setAttribute('aria-expanded', 'false');
            document.body.style.overflow = '';
        };

        const openSidebar = () => {
            sidebar.classList.add('open');
            overlay?.classList.add('show');
            toggle?.setAttribute('aria-expanded', 'true');

            if (window.innerWidth < 1200) {
                document.body.style.overflow = 'hidden';
            }
        };

        toggle?.addEventListener('click', () => {
            if (sidebar.classList.contains('open')) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });

        overlay?.addEventListener('click', closeSidebar);

        sidebar.querySelectorAll('a').forEach((link) => {
            link.addEventListener('click', () => {
                if (window.innerWidth < 1200) {
                    closeSidebar();
                }
            });
        });

        window.addEventListener('resize', () => {
            if (window.innerWidth >= 1200) {
                closeSidebar();
            }
        });

        sidebar.querySelectorAll('.ars-nav-group-toggle').forEach((groupToggle) => {
            const targetId = groupToggle.dataset.navTarget;
            const group = targetId ? document.getElementById(targetId) : null;

            if (!group) {
                return;
            }

            const storageKey = `arsflow-nav-${targetId}`;
            let savedState = null;

            try {
                savedState = window.localStorage.getItem(storageKey);
            } catch (error) {
                savedState = null;
            }

            const setCollapsed = (collapsed) => {
                group.classList.toggle('collapsed', collapsed);
                groupToggle.setAttribute('aria-expanded', String(!collapsed));
            };

            // Todos los grupos inician contraídos, salvo que el usuario los haya expandido.
            setCollapsed(savedState !== 'expanded');

            groupToggle.addEventListener('click', () => {
                const collapsed = !group.classList.contains('collapsed');
                setCollapsed(collapsed);

                try {
                    window.localStorage.setItem(
                        storageKey,
                        collapsed ? 'collapsed' : 'expanded'
                    );
                } catch (error) {
                    // El menú sigue funcionando aunque el navegador bloquee storage.
                }
            });
        });

        if (searchInput && searchResults) {
            const modules = Array.from(sidebar.querySelectorAll('.ars-nav-link[href]'))
                .filter((link) => !link.classList.contains('ars-logout-link'))
                .map((link) => ({
                    type: 'Módulo',
                    label: link.textContent.trim().replace(/\s+/g, ' '),
                    detail: 'Ir al módulo',
                    href: link.getAttribute('href'),
                    icon: link.querySelector('i')?.className || 'fas fa-arrow-right'
                }));
            let searchTimer = null;
            let searchController = null;

            const hideResults = () => {
                searchResults.classList.remove('show');
                searchResults.innerHTML = '';
            };

            const renderItems = (items, emptyMessage = 'No se encontraron resultados') => {
                searchResults.innerHTML = '';

                if (!items.length) {
                    const empty = document.createElement('div');
                    empty.className = 'ars-search-empty';
                    empty.textContent = emptyMessage;
                    searchResults.appendChild(empty);
                } else {
                    items.forEach((item) => {
                        const link = document.createElement('a');
                        const icon = document.createElement('i');
                        const copy = document.createElement('span');
                        const heading = document.createElement('span');
                        const label = document.createElement('strong');
                        const type = document.createElement('small');
                        const detail = document.createElement('small');

                        link.className = 'ars-search-result';
                        link.href = item.href;
                        icon.className = item.icon;
                        copy.className = 'ars-search-result-copy';
                        heading.className = 'ars-search-result-heading';
                        type.className = 'ars-search-result-type';
                        detail.className = 'ars-search-result-detail';
                        label.textContent = item.label;
                        type.textContent = item.type;
                        detail.textContent = item.detail || '';

                        heading.append(label, type);
                        copy.append(heading, detail);
                        link.append(icon, copy);
                        searchResults.appendChild(link);
                    });
                }
                searchResults.classList.add('show');
            };

            const renderResults = () => {
                const query = searchInput.value.trim().toLocaleLowerCase('es');

                if (!query) {
                    hideResults();
                    return;
                }

                const moduleMatches = modules
                    .filter((module) => module.label.toLocaleLowerCase('es').includes(query))
                    .slice(0, 5);

                if (query.length < 2) {
                    renderItems(moduleMatches, 'Escribe al menos 2 caracteres para buscar datos');
                    return;
                }

                renderItems(moduleMatches, 'Buscando en el sistema...');
                window.clearTimeout(searchTimer);
                searchController?.abort();
                searchTimer = window.setTimeout(async () => {
                    searchController = new AbortController();
                    try {
                        const params = new URLSearchParams({ q: searchInput.value.trim() });
                        const response = await fetch(`/api/busqueda-global?${params}`, {
                            headers: { Accept: 'application/json' },
                            signal: searchController.signal
                        });
                        if (!response.ok) {
                            throw new Error('No se pudo completar la búsqueda');
                        }
                        const data = await response.json();
                        if (searchInput.value.trim().toLocaleLowerCase('es') !== query) {
                            return;
                        }
                        const dataResults = (data.resultados || []).map((item) => ({
                            type: item.tipo,
                            label: item.titulo,
                            detail: item.detalle,
                            href: item.url,
                            icon: item.icono || 'fas fa-magnifying-glass'
                        }));
                        renderItems([...moduleMatches, ...dataResults]);
                    } catch (error) {
                        if (error.name !== 'AbortError') {
                            renderItems(moduleMatches, 'No fue posible buscar en este momento');
                        }
                    }
                }, 250);
            };

            searchInput.addEventListener('input', renderResults);
            searchInput.addEventListener('focus', renderResults);

            searchInput.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    searchInput.blur();
                    hideResults();
                    return;
                }

                if (event.key === 'Enter') {
                    const firstResult = searchResults.querySelector('.ars-search-result');
                    if (firstResult) {
                        event.preventDefault();
                        firstResult.click();
                    }
                }
            });

            document.addEventListener('click', (event) => {
                if (!event.target.closest('.ars-search')) {
                    hideResults();
                }
            });

            document.addEventListener('keydown', (event) => {
                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
                    event.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                }

                if (event.key === 'Escape' && sidebar.classList.contains('open')) {
                    closeSidebar();
                }
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAppShell);
    } else {
        initAppShell();
    }
})();
