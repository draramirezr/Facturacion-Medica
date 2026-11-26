/* Historia de emergencia: filas de medicamentos y materiales del almacén. */
(() => {
    'use strict';

    document.querySelectorAll('[data-alm-consumo]').forEach((caja) => {
        const filas = caja.querySelector('[data-alm-filas]');
        const plantilla = caja.querySelector('template[data-alm-plantilla]');
        if (!filas || !plantilla) {
            return;
        }

        // Unidad visible y tope de cantidad según lo disponible del artículo.
        // El servidor vuelve a validar con la fila bloqueada.
        function actualizar(fila) {
            const select = fila.querySelector('[data-alm-articulo]');
            const cantidad = fila.querySelector('[data-alm-cantidad]');
            const unidad = fila.querySelector('[data-alm-unidad]');
            const opcion = select.options[select.selectedIndex];
            if (opcion && opcion.value) {
                unidad.textContent = opcion.dataset.unidad || '';
                cantidad.max = opcion.dataset.disponible || '';
                cantidad.required = true;
            } else {
                unidad.textContent = '—';
                cantidad.max = '99999999.99';
                cantidad.required = false;
            }
        }

        function nuevaFila() {
            const fila = plantilla.content.firstElementChild.cloneNode(true);
            filas.appendChild(fila);
            actualizar(fila);
            fila.querySelector('[data-alm-articulo]').focus();
        }

        filas.querySelectorAll('[data-alm-fila]').forEach(actualizar);

        caja.addEventListener('change', (evento) => {
            if (evento.target.matches('[data-alm-articulo]')) {
                actualizar(evento.target.closest('[data-alm-fila]'));
            }
        });

        caja.addEventListener('click', (evento) => {
            if (evento.target.closest('[data-alm-agregar]')) {
                nuevaFila();
                return;
            }
            const quitar = evento.target.closest('[data-alm-quitar]');
            if (!quitar) {
                return;
            }
            const fila = quitar.closest('[data-alm-fila]');
            if (filas.querySelectorAll('[data-alm-fila]').length > 1) {
                fila.remove();
            } else {
                fila.querySelector('[data-alm-articulo]').value = '';
                fila.querySelector('[data-alm-cantidad]').value = '';
                actualizar(fila);
            }
        });
    });
})();
