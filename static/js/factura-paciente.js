/* Factura al paciente: líneas con o sin seguro, totales, cambio y sugerencias.
 * Con seguro: Monto = Cubre ARS + Diferencia. Al escribir uno de los dos,
 * el otro se calcula. El paciente paga la diferencia; lo de la ARS pasa a
 * Estado de Facturación. */
(() => {
    'use strict';

    const form = document.getElementById('facturaPacienteForm');
    if (!form) {
        return;
    }
    const tabla = document.getElementById('fpTabla');
    const plantilla = document.getElementById('fpLineaTpl');
    const totalEl = document.getElementById('fpTotal');
    const cambioEl = document.getElementById('fpCambio');
    const metodo = document.getElementById('metodo_pago');
    const recibido = document.getElementById('monto_recibido');
    const bloqueEfectivo = document.getElementById('fpEfectivo');
    const bloqueReferencia = document.getElementById('fpReferencia');
    const bloqueCredito = document.getElementById('fpCreditoFiscal');
    const bloquePago = document.getElementById('fpPago');
    const bloqueComprobante = document.getElementById('fpComprobante');
    const datosSeguro = document.getElementById('fpSeguroDatos');
    const resumenSeguro = document.getElementById('fpResumenSeguro');
    const totalServiciosEl = document.getElementById('fpTotalServicios');
    const totalArsEl = document.getElementById('fpTotalArs');
    const sinCobro = document.getElementById('fpSinCobro');
    const botonEmitir = document.getElementById('fpEmitir');
    const medico = document.getElementById('medico_id');
    const arsSelect = document.getElementById('ars_id');
    const nssInput = document.getElementById('nss');
    const sugerencias = document.getElementById('fpSugerencias');
    const pacienteInput = document.getElementById('paciente_id');

    const numero = (valor) => {
        const n = Number.parseFloat(String(valor || '').replace(/,/g, ''));
        return Number.isFinite(n) ? n : 0;
    };
    const redondear = (n) => Math.round(n * 100) / 100;
    const moneda = (n) => n.toLocaleString('es-DO', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    const lineas = () => Array.from(tabla.querySelectorAll('[data-fp-linea]'));
    const campo = (linea, selector) => linea.querySelector(selector);

    function sincronizarSeguro(linea) {
        const activo = campo(linea, '[data-fp-seguro]').checked;
        campo(linea, '[name="linea_seguro"]').value = activo ? '1' : '0';
        campo(linea, '[data-fp-seguro-fila]').hidden = !activo;
        const cantidad = campo(linea, '[name="linea_cantidad"]');
        cantidad.readOnly = activo;
        if (activo) {
            cantidad.value = '1';
        }
        campo(linea, '[name="linea_autorizacion"]').required = activo;
    }

    // Monto = Cubre ARS + Diferencia; recalcula el campo que no se está editando.
    function completarSeguro(linea, origen) {
        const monto = numero(campo(linea, '[name="linea_precio"]').value);
        const cubre = campo(linea, '[data-fp-cubre]');
        const diferencia = campo(linea, '[data-fp-diferencia]');
        if (origen === 'diferencia') {
            cubre.value = diferencia.value === '' ? '' : redondear(Math.max(0, monto - numero(diferencia.value))).toFixed(2);
        } else if (cubre.value !== '') {
            diferencia.value = redondear(Math.max(0, monto - numero(cubre.value))).toFixed(2);
        } else if (diferencia.value !== '') {
            cubre.value = redondear(Math.max(0, monto - numero(diferencia.value))).toFixed(2);
        }
    }

    function recalcular() {
        let pagaPaciente = 0;
        let totalServicios = 0;
        let cubreArs = 0;
        let haySeguro = false;
        lineas().forEach((linea) => {
            const conSeguro = campo(linea, '[data-fp-seguro]').checked;
            const cantidad = Math.max(0, Math.trunc(numero(campo(linea, '[name="linea_cantidad"]').value)));
            const monto = numero(campo(linea, '[name="linea_precio"]').value);
            let paga;
            if (conSeguro) {
                haySeguro = true;
                const cubre = Math.min(monto, numero(campo(linea, '[data-fp-cubre]').value));
                paga = redondear(monto - cubre);
                cubreArs += cubre;
                totalServicios += monto;
            } else {
                paga = redondear(cantidad * monto);
                totalServicios += paga;
            }
            campo(linea, '[data-fp-subtotal]').textContent = moneda(paga);
            pagaPaciente += paga;
        });
        pagaPaciente = redondear(pagaPaciente);
        totalEl.textContent = moneda(pagaPaciente);
        totalServiciosEl.textContent = moneda(redondear(totalServicios));
        totalArsEl.textContent = moneda(redondear(cubreArs));

        datosSeguro.hidden = !haySeguro;
        resumenSeguro.hidden = !haySeguro;
        arsSelect.required = haySeguro;
        nssInput.required = haySeguro;
        medico.required = haySeguro;

        // Si el seguro cubre todo, no hay factura ni cobro al paciente.
        const sinPago = haySeguro && pagaPaciente <= 0;
        bloquePago.hidden = sinPago;
        bloqueComprobante.hidden = sinPago;
        sinCobro.hidden = !sinPago;
        botonEmitir.querySelector('span').textContent = sinPago ? 'Registrar para la ARS' : 'Emitir y cobrar';

        const esEfectivo = metodo.value === 'Efectivo';
        const pagado = numero(recibido.value);
        if (!sinPago && esEfectivo && pagado > 0 && pagado >= pagaPaciente) {
            cambioEl.hidden = false;
            cambioEl.querySelector('span').textContent = moneda(pagado - pagaPaciente);
        } else {
            cambioEl.hidden = true;
        }
    }

    function nuevaLinea() {
        const fragmento = plantilla.content.cloneNode(true);
        const linea = fragmento.querySelector('[data-fp-linea]');
        tabla.appendChild(fragmento);
        return linea;
    }

    function agregarLinea(descripcion = '', precio = '', servicioId = '', conSeguro = false) {
        let linea = lineas().find((l) => !campo(l, '[name="linea_descripcion"]').value.trim()
            && !campo(l, '[name="linea_precio"]').value);
        if (!linea) {
            linea = nuevaLinea();
        }
        campo(linea, '[name="linea_descripcion"]').value = descripcion;
        campo(linea, '[name="linea_precio"]').value = precio;
        campo(linea, '[name="linea_servicio_id"]').value = servicioId;
        campo(linea, '[data-fp-seguro]').checked = conSeguro;
        sincronizarSeguro(linea);
        const destino = conSeguro ? '[name="linea_autorizacion"]'
            : (precio === '' ? '[name="linea_precio"]' : '[name="linea_descripcion"]');
        campo(linea, destino).focus();
        recalcular();
    }

    form.addEventListener('input', (evento) => {
        const linea = evento.target.closest('[data-fp-linea]');
        if (linea && campo(linea, '[data-fp-seguro]').checked) {
            if (evento.target.matches('[data-fp-diferencia]')) {
                completarSeguro(linea, 'diferencia');
            } else if (evento.target.matches('[data-fp-cubre], [name="linea_precio"]')) {
                completarSeguro(linea, 'cubre');
            }
        }
        if (evento.target.matches('[name="linea_autorizacion"]')) {
            const posicion = evento.target.selectionStart;
            evento.target.value = evento.target.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
            evento.target.setSelectionRange(posicion, posicion);
        }
        recalcular();
    });
    form.addEventListener('change', (evento) => {
        if (evento.target.matches('[data-fp-seguro]')) {
            const linea = evento.target.closest('[data-fp-linea]');
            sincronizarSeguro(linea);
            if (evento.target.checked) {
                completarSeguro(linea, 'cubre');
                campo(linea, '[name="linea_autorizacion"]').focus();
            }
            recalcular();
        }
    });
    form.addEventListener('click', (evento) => {
        const quitar = evento.target.closest('[data-fp-quitar]');
        if (quitar) {
            const todas = lineas();
            if (todas.length > 1) {
                quitar.closest('[data-fp-linea]').remove();
            } else {
                const linea = todas[0];
                linea.querySelectorAll('input').forEach((input) => {
                    if (input.type === 'checkbox') {
                        input.checked = false;
                    } else if (input.name === 'linea_cantidad') {
                        input.value = '1';
                    } else if (input.name === 'linea_seguro') {
                        input.value = '0';
                    } else {
                        input.value = '';
                    }
                });
                sincronizarSeguro(linea);
            }
            recalcular();
            return;
        }
        const concepto = evento.target.closest('[data-fp-concepto]');
        if (concepto) {
            const texto = concepto.dataset.fpConcepto;
            // "Diferencia / copago ARS" nace marcada con seguro.
            agregarLinea(/ARS/.test(texto) ? 'Consulta' : texto, '', '', /ARS/.test(texto));
            return;
        }
        const sugerida = evento.target.closest('[data-fp-sugerida]');
        if (sugerida) {
            agregarLinea(sugerida.dataset.fpSugerida);
        }
    });
    document.getElementById('fpAgregar').addEventListener('click', () => {
        nuevaLinea();
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

    // Al elegir paciente: completa NSS y ARS si los tiene y muestra consultas recientes.
    // reemplazar=true al elegir otro paciente; al cargar solo rellena lo vacío.
    function completarDatosPaciente(reemplazar) {
        if (!pacienteInput) {
            return;
        }
        if ((reemplazar || !nssInput.value) && pacienteInput.dataset.nss !== undefined) {
            nssInput.value = pacienteInput.dataset.nss || '';
        }
        if ((reemplazar || !arsSelect.value) && pacienteInput.dataset.arsId) {
            arsSelect.value = pacienteInput.dataset.arsId;
        }
    }
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
        pacienteInput.addEventListener('change', () => {
            completarDatosPaciente(true);
            cargarSugerencias();
        });
        completarDatosPaciente(false);
        cargarSugerencias();
    }

    lineas().forEach((linea) => {
        sincronizarSeguro(linea);
        if (campo(linea, '[data-fp-seguro]').checked) {
            completarSeguro(linea, 'cubre');
        }
    });
    ajustarPago();
})();
