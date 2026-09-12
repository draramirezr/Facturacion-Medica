(() => {
    function setPatient(hidden, patient) {
        hidden.value = patient?.id || '';
        const values = {
            cedula: patient?.cedula || '',
            nss: patient?.nss || '',
            telefono: patient?.telefono || '',
            fechaNacimiento: patient?.fecha_nacimiento || '',
            sexo: patient?.sexo || '',
            direccion: patient?.direccion || '',
            arsNombre: patient?.ars_nombre || '',
            nombrePariente: patient?.nombre_pariente || '',
            telefonoPariente: patient?.telefono_pariente || '',
        };
        Object.entries(values).forEach(([key, value]) => {
            hidden.dataset[key] = value;
        });
        hidden.dispatchEvent(new CustomEvent('patient:selected', {
            bubbles: true,
            detail: patient || null,
        }));
        hidden.dispatchEvent(new Event('change', {bubbles: true}));
    }

    document.querySelectorAll('[data-patient-search]').forEach((component) => {
        const input = component.querySelector('.patient-search__input');
        const hidden = component.querySelector('input[type="hidden"]');
        const results = component.querySelector('.patient-search__results');
        const clear = component.querySelector('.patient-search__clear');
        const required = component.dataset.required === 'true';
        let timer;
        let requestController;
        let matches = [];
        let activeIndex = -1;

        const closeResults = () => {
            results.hidden = true;
            results.replaceChildren();
            input.setAttribute('aria-expanded', 'false');
            activeIndex = -1;
        };

        const validate = () => {
            input.setCustomValidity(
                required && !hidden.value
                    ? 'Selecciona un paciente de los resultados.'
                    : ''
            );
        };

        const choose = (patient) => {
            input.value = patient.nombre;
            setPatient(hidden, patient);
            clear.hidden = false;
            validate();
            closeResults();
        };

        const chooseById = async (id) => {
            if (!id) {
                input.value = '';
                setPatient(hidden, null);
                clear.hidden = true;
                validate();
                return;
            }
            try {
                const response = await fetch(
                    `${component.dataset.endpoint}?id=${encodeURIComponent(id)}`,
                    {
                        credentials: 'same-origin',
                        headers: {Accept: 'application/json'},
                    }
                );
                if (!response.ok) throw new Error('Patient lookup failed');
                const patient = (await response.json()).resultados?.[0];
                if (patient) choose(patient);
            } catch (error) {
                setPatient(hidden, null);
                validate();
            }
        };

        const render = () => {
            results.replaceChildren();
            if (!matches.length) {
                const empty = document.createElement('div');
                empty.className = 'patient-search__empty';
                empty.textContent = 'No se encontraron pacientes.';
                results.appendChild(empty);
            } else {
                matches.forEach((patient, index) => {
                    const button = document.createElement('button');
                    button.type = 'button';
                    button.className = 'patient-search__result';
                    button.setAttribute('role', 'option');
                    button.dataset.index = String(index);

                    const name = document.createElement('strong');
                    name.textContent = patient.nombre;
                    const detail = document.createElement('small');
                    detail.textContent = [
                        patient.cedula && `Cédula: ${patient.cedula}`,
                        patient.nss && `NSS: ${patient.nss}`,
                        patient.telefono,
                    ].filter(Boolean).join(' · ') || 'Sin referencias registradas';
                    button.append(name, detail);
                    button.addEventListener('click', () => choose(patient));
                    results.appendChild(button);
                });
            }
            results.hidden = false;
            input.setAttribute('aria-expanded', 'true');
        };

        const search = async () => {
            const term = input.value.trim();
            if (term.length < 2) {
                matches = [];
                closeResults();
                return;
            }
            requestController?.abort();
            requestController = new AbortController();
            try {
                const response = await fetch(
                    `${component.dataset.endpoint}?q=${encodeURIComponent(term)}`,
                    {
                        credentials: 'same-origin',
                        headers: {Accept: 'application/json'},
                        signal: requestController.signal,
                    }
                );
                if (!response.ok) throw new Error('Patient search failed');
                matches = (await response.json()).resultados || [];
                render();
            } catch (error) {
                if (error.name !== 'AbortError') {
                    matches = [];
                    closeResults();
                }
            }
        };

        input.addEventListener('input', () => {
            if (hidden.value) setPatient(hidden, null);
            clear.hidden = !input.value;
            validate();
            clearTimeout(timer);
            timer = setTimeout(search, 250);
        });

        input.addEventListener('keydown', (event) => {
            const options = [...results.querySelectorAll('[role="option"]')];
            if (event.key === 'Escape') {
                closeResults();
                return;
            }
            if (!options.length || results.hidden) return;
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                const increment = event.key === 'ArrowDown' ? 1 : -1;
                activeIndex = (activeIndex + increment + options.length)
                    % options.length;
                options.forEach((option, index) => {
                    option.classList.toggle('active', index === activeIndex);
                });
                options[activeIndex].scrollIntoView({block: 'nearest'});
            } else if (event.key === 'Enter' && activeIndex >= 0) {
                event.preventDefault();
                choose(matches[activeIndex]);
            }
        });

        clear.addEventListener('click', () => {
            input.value = '';
            setPatient(hidden, null);
            clear.hidden = true;
            validate();
            closeResults();
            input.focus();
        });

        component.addEventListener('patient:select-id', (event) => {
            chooseById(event.detail?.id);
        });

        component.closest('form')?.addEventListener('submit', (event) => {
            validate();
            if (!input.checkValidity()) {
                event.preventDefault();
                input.reportValidity();
            }
        });

        document.addEventListener('click', (event) => {
            if (!component.contains(event.target)) closeResults();
        });

        input.setAttribute('aria-expanded', 'false');
        validate();
        if (hidden.value) {
            const initial = Object.fromEntries(
                Object.entries(hidden.dataset).map(([key, value]) => [key, value])
            );
            initial.id = hidden.value;
            initial.fecha_nacimiento = initial.fechaNacimiento;
            initial.ars_nombre = initial.arsNombre;
            initial.nombre_pariente = initial.nombrePariente;
            initial.telefono_pariente = initial.telefonoPariente;
            setPatient(hidden, initial);
        }
    });

    document.querySelectorAll('[data-patient-directory-search]').forEach((component) => {
        const form = component.closest('form');
        const input = component.querySelector('.patient-search__input');
        const results = component.querySelector('.patient-search__results');
        const clear = component.querySelector('.patient-search__clear');
        let timer;
        let requestController;
        let matches = [];
        let activeIndex = -1;

        const closeResults = () => {
            results.hidden = true;
            results.replaceChildren();
            input.setAttribute('aria-expanded', 'false');
            activeIndex = -1;
        };

        const choose = (patient) => {
            input.value = patient.nombre;
            clear.hidden = false;
            closeResults();
            form?.requestSubmit();
        };

        const render = () => {
            results.replaceChildren();
            if (!matches.length) {
                const empty = document.createElement('div');
                empty.className = 'patient-search__empty';
                empty.textContent = 'No se encontraron pacientes.';
                results.appendChild(empty);
            } else {
                matches.forEach((patient, index) => {
                    const option = document.createElement('button');
                    option.type = 'button';
                    option.className = 'patient-search__result';
                    option.setAttribute('role', 'option');
                    option.dataset.index = String(index);

                    const name = document.createElement('strong');
                    name.textContent = patient.nombre;
                    const detail = document.createElement('small');
                    detail.textContent = [
                        patient.cedula && `Cédula: ${patient.cedula}`,
                        patient.nss && `NSS: ${patient.nss}`,
                        patient.telefono && `Teléfono: ${patient.telefono}`,
                    ].filter(Boolean).join(' · ') || 'Sin referencias registradas';

                    option.append(name, detail);
                    option.addEventListener('click', () => choose(patient));
                    results.appendChild(option);
                });
            }
            results.hidden = false;
            input.setAttribute('aria-expanded', 'true');
        };

        const search = async () => {
            const term = input.value.trim();
            if (term.length < 2) {
                matches = [];
                closeResults();
                return;
            }

            requestController?.abort();
            requestController = new AbortController();
            try {
                const response = await fetch(
                    `${component.dataset.endpoint}?q=${encodeURIComponent(term)}`,
                    {
                        credentials: 'same-origin',
                        headers: {Accept: 'application/json'},
                        signal: requestController.signal,
                    }
                );
                if (!response.ok) throw new Error('Patient directory search failed');
                matches = (await response.json()).resultados || [];
                render();
            } catch (error) {
                if (error.name !== 'AbortError') {
                    matches = [];
                    closeResults();
                }
            }
        };

        input.addEventListener('input', () => {
            clear.hidden = !input.value;
            clearTimeout(timer);
            timer = setTimeout(search, 250);
        });

        input.addEventListener('keydown', (event) => {
            const options = [...results.querySelectorAll('[role="option"]')];
            if (event.key === 'Escape') {
                closeResults();
                return;
            }
            if (!options.length || results.hidden) return;
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                const increment = event.key === 'ArrowDown' ? 1 : -1;
                activeIndex = (activeIndex + increment + options.length)
                    % options.length;
                options.forEach((option, index) => {
                    option.classList.toggle('active', index === activeIndex);
                });
                options[activeIndex].scrollIntoView({block: 'nearest'});
            } else if (event.key === 'Enter' && activeIndex >= 0) {
                event.preventDefault();
                choose(matches[activeIndex]);
            }
        });

        clear.addEventListener('click', () => {
            input.value = '';
            clear.hidden = true;
            closeResults();
            input.focus();
        });

        document.addEventListener('click', (event) => {
            if (!component.contains(event.target)) closeResults();
        });

        input.setAttribute('aria-expanded', 'false');
    });
})();
