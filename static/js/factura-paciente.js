/* Formulario de factura al paciente: líneas, total, cambio y sugerencias. */
(() => {
    'use strict';

    const form = document.getElementById('facturaPacienteForm');
    if (!form) {
        return;
    }
    const cuerpo = document.getElementById('fpLineas');
    const plantilla = document.getElementById('fpLineaTpl');
    const totalEl = document.getElementById('fpTotal');
    const cambioEl = document.getElementById('fpCambio');
    const metodo = document.getElementById('metodo_pago');
    const recibido = document.getElementById('monto_recibido');
    const bloqueEfectivo = document.getElementById('fpEfectivo');
    const bloqueReferencia = document.getElementById('fpReferencia');
    const bloqueCredito = document.getElementById('fpCreditoFiscal');
    const sugerencias = document.getElementById('fpSugerencias');

    const numero = (valor) => {
        const n = Number.parseFloat(String(valor || '').replace(/,/g, ''));
        return Number.isFinite(n) ? n : 0;
    };
    const moneda = (n) => n.toLocaleString('es-DO', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

    function recalcular() {
        let total = 0;
        cuerpo.querySelectorAll('[data-fp-linea]').forEach((fila) => {
            const cantidad = Math.max(0, Math.trunc(numero(fila.querySelector('[name="linea_cantidad"]').value)));
            const precio = numero(fila.querySelector('[name="linea_precio"]').value);
            const subtotal = Math.round(cantidad * precio * 100) / 100;
            fila.querySelector('[data-fp-subtotal]').textContent = moneda(subtotal);
            total += subtotal;
        });
        total = Math.round(total * 100) / 100;
        totalEl.textContent = moneda(total);
        const esEfectivo = metodo.value === 'Efectivo';
        const pagado = numero(recibido.value);
        if (esEfectivo && pagado > 0 && pagado >= total) {
            cambioEl.hidden = false;
            cambioEl.querySelector('span').textContent = moneda(pagado - total);
        } else {
            cambioEl.hidden = true;
        }
    }

    function agregarLinea(descripcion = '', precio = '', servicioId = '') {
        let fila = null;
        // Reutiliza la primera fila vacía antes de crear otra.
        cuerpo.querySelectorAll('[data-fp-linea]').forEach((f) => {
            if (!fila && !f.querySelector('[name="linea_descripcion"]').value.trim()
                && !f.querySelector('[name="linea_precio"]').value) {
                fila = f;
            }
        });
        if (!fila) {
            fila = plantilla.content.firstElementChild.cloneNode(true);
            cuerpo.appendChild(fila);
        }
        fila.querySelector('[name="linea_descripcion"]').value = descripcion;
        fila.querySelector('[name="linea_precio"]').value = precio;
        fila.querySelector('[name="linea_servicio_id"]').value = servicioId;
        const destino = precio === '' ? '[name="linea_precio"]' : '[name="linea_descripcion"]';
        fila.querySelector(destino).focus();
        recalcular();
    }

    form.addEventListener('input', recalcular);
    form.addEventListener('click', (evento) => {
        const quitar = evento.target.closest('[data-fp-quitar]');
        if (quitar) {
            const filas = cuerpo.querySelectorAll('[data-fp-linea]');
            if (filas.length > 1) {
                quitar.closest('[data-fp-linea]').remove();
            } else {
                filas[0].querySelectorAll('input').forEach((input) => {
                    input.value = input.name === 'linea_cantidad' ? '1' : '';
                });
            }
            recalcular();
            return;
        }
        const concepto = evento.target.closest('[data-fp-concepto]');
        if (concepto) {
            agregarLinea(concepto.dataset.fpConcepto);
            return;
        }
        const sugerida = evento.target.closest('[data-fp-sugerida]');
        if (sugerida) {
            agregarLinea(sugerida.dataset.fpSugerida);
        }
    });
    document.getElementById('fpAgregar').addEventListener('click', () => {
        cuerpo.appendChild(plantilla.content.firstElementChild.cloneNode(true));
        recalcular();
    });

    const catalogo = document.getElementById('fpServicio');
    if (catalogo) {
        catalogo.addEventListener('change', () => {
            const opcion = catalogo.selectedOptions[0];
            if (opcion && opcion.value) {
                agregarLinea(opcion.textContent.trim(), opcion.dataset.precio || '', opcion.value);
            }
            catalogo.value = '';
        });
    }

    function ajustarPago() {
        const esEfectivo = metodo.value === 'Efectivo';
        bloqueEfectivo.hidden = !esEfectivo;
        bloqueReferencia.hidden = esEfectivo;
        recalcular();
    }
    metodo.addEventListener('change', ajustarPago);

    form.querySelectorAll('[name="tipo_comprobante"]').forEach((radio) => {
        radio.addEventListener('change', () => {
            bloqueCredito.hidden = form.querySelector('[name="tipo_comprobante"]:checked').value !== 'B01';
        });
    });

    // Sugerencias: consultas registradas del paciente (diferencia que no cubre la ARS).
    const pacienteInput = document.getElementById('paciente_id');
    async function cargarSugerencias() {
        sugerencias.querySelectorAll('.fp-sugerencia').forEach((item) => item.remove());
        sugerencias.hidden = true;
        const id = pacienteInput && pacienteInput.value;
        if (!id) {
            return;
        }
        const url = form.dataset.consultasUrl.replace(/\/0\/consultas-recientes$/, `/${encodeURIComponent(id)}/consultas-recientes`);
        try {
            const respuesta = await fetch(url, { headers: { Accept: 'application/json' } });
            if (!respuesta.ok) {
                return;
            }
            const consultas = await respuesta.json();
            consultas.forEach((consulta) => {
                const fila = document.createElement('div');
                fila.className = 'fp-sugerencia';
                const texto = document.createElement('span');
                texto.textContent = `${consulta.fecha} · ${consulta.servicio}${consulta.ars ? ' · ' + consulta.ars : ''}`;
                const boton = document.createElement('button');
                boton.type = 'button';
                boton.className = 'fp-chip';
                boton.dataset.fpSugerida = `Diferencia ${consulta.servicio}${consulta.ars ? ' (' + consulta.ars + ')' : ''} ${consulta.fecha}`.slice(0, 500);
                boton.textContent = 'Cobrar diferencia';
                fila.append(texto, boton);
                sugerencias.appendChild(fila);
            });
            sugerencias.hidden = consultas.length === 0;
        } catch (error) {
            sugerencias.hidden = true;
        }
    }
    if (pacienteInput) {
        pacienteInput.addEventListener('change', cargarSugerencias);
        cargarSugerencias();
    }

    ajustarPago();
})();
