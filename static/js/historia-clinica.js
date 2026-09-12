(function () {
    'use strict';

    const createElement = (tagName, className, text) => {
        const element = document.createElement(tagName);
        if (className) {
            element.className = className;
        }
        if (text !== undefined) {
            element.textContent = text;
        }
        return element;
    };

    const buildField = (field) => {
        const columnClass = field.type === 'textarea' ? 'col-md-6' : 'col-md-4';
        const wrapper = createElement('div', `${columnClass} mb-3`);
        if (field.depends_on) {
            wrapper.dataset.dependsField = field.depends_on.field;
            wrapper.dataset.dependsValue = field.depends_on.equals;
        }
        const id = `especialidad_${field.name}`;
        const label = createElement(
            'label',
            'form-label',
            `${field.label}${field.required ? ' *' : ''}`
        );
        label.htmlFor = id;
        wrapper.appendChild(label);

        let control;
        if (field.type === 'textarea') {
            control = createElement('textarea', 'form-control');
            control.rows = 2;
            control.maxLength = field.max_length || 5000;
        } else if (field.type === 'select') {
            control = createElement('select', 'form-select');
            const emptyOption = createElement('option', '', 'Seleccione...');
            emptyOption.value = '';
            control.appendChild(emptyOption);
            (field.options || []).forEach((optionValue) => {
                const option = createElement('option', '', optionValue);
                option.value = optionValue;
                control.appendChild(option);
            });
        } else {
            control = createElement('input', 'form-control');
            control.type = field.type || 'text';
            ['min', 'max', 'step', 'max_length'].forEach((property) => {
                if (field[property] === undefined) {
                    return;
                }
                const attribute = property === 'max_length' ? 'maxlength' : property;
                control.setAttribute(attribute, field[property]);
            });
        }
        control.id = id;
        control.name = id;
        wrapper.appendChild(control);
        return wrapper;
    };

    const wireConditions = (sections) => {
        sections.querySelectorAll('[data-depends-field]').forEach((wrapper) => {
            const controller = sections.querySelector(
                `#especialidad_${CSS.escape(wrapper.dataset.dependsField)}`
            );
            const dependentControl = wrapper.querySelector('input, select, textarea');
            if (!controller || !dependentControl) {
                return;
            }
            const updateVisibility = () => {
                const visible = controller.value === wrapper.dataset.dependsValue;
                wrapper.classList.toggle('d-none', !visible);
                dependentControl.disabled = !visible;
                if (!visible) {
                    dependentControl.value = '';
                }
            };
            controller.addEventListener('change', updateVisibility);
            updateVisibility();
        });
    };

    const renderSchema = (schema, title, sections) => {
        title.textContent = schema.label || 'Evaluación especializada';
        sections.replaceChildren();
        (schema.sections || []).forEach((sectionData) => {
            const section = createElement('section', 'mb-4');
            section.appendChild(
                createElement('h2', 'hc-section-title', sectionData.title)
            );
            const row = createElement('div', 'row');
            (sectionData.fields || []).forEach((field) => {
                row.appendChild(buildField(field));
            });
            section.appendChild(row);
            sections.appendChild(section);
        });
        wireConditions(sections);
    };

    document.addEventListener('DOMContentLoaded', () => {
        const weight = document.getElementById('peso');
        const height = document.getElementById('talla');
        const bmi = document.getElementById('imc');
        const calculateBmi = () => {
            const weightValue = Number.parseFloat(weight?.value);
            const heightValue = Number.parseFloat(height?.value);
            if (bmi) {
                bmi.value = weightValue > 0 && heightValue > 0
                    ? (weightValue / (heightValue * heightValue)).toFixed(2)
                    : '';
            }
        };
        weight?.addEventListener('input', calculateBmi);
        height?.addEventListener('input', calculateBmi);
        calculateBmi();

        const doctor = document.getElementById('medico_id');
        const container = document.getElementById('specialtyFields');
        const title = document.getElementById('specialtyTitle');
        const sections = document.getElementById('specialtySections');
        if (!doctor || !container || !title || !sections) {
            return;
        }
        wireConditions(sections);

        doctor.addEventListener('change', async () => {
            if (!doctor.value) {
                title.textContent = 'Evaluación especializada';
                sections.replaceChildren(
                    createElement(
                        'p',
                        'hc-specialty-empty',
                        'Seleccione un médico para cargar el formulario de su especialidad.'
                    )
                );
                return;
            }
            title.textContent = 'Cargando formulario…';
            sections.replaceChildren();
            try {
                const endpoint = container.dataset.schemaUrl.replace(
                    /0$/,
                    encodeURIComponent(doctor.value)
                );
                const response = await fetch(endpoint, {
                    credentials: 'same-origin',
                    headers: {Accept: 'application/json'}
                });
                if (!response.ok) {
                    throw new Error('No fue posible obtener la plantilla');
                }
                renderSchema(await response.json(), title, sections);
            } catch (error) {
                title.textContent = 'Formulario no disponible';
                sections.replaceChildren(
                    createElement(
                        'p',
                        'text-danger',
                        'No se pudo cargar la especialidad. Recargue la página e inténtelo nuevamente.'
                    )
                );
            }
        });
    });
}());
