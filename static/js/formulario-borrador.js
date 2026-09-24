(function () {
    'use strict';

    const form = document.querySelector('[data-clinic-draft]');
    if (!form) {
        return;
    }
    const clave = 'clinicrd-draft:' + form.getAttribute('data-clinic-draft');
    const bannerId = 'clinicrd-draft-banner';

    const mostrarBanner = (texto, tipo) => {
        let banner = document.getElementById(bannerId);
        if (!banner) {
            banner = document.createElement('div');
            banner.id = bannerId;
            banner.setAttribute('role', 'status');
            banner.style.cssText = 'padding:0.75rem 1rem;margin-bottom:1rem;border-radius:12px;font-weight:700;';
            form.parentNode.insertBefore(banner, form);
        }
        banner.style.background = tipo === 'offline' ? '#fff7ed' : '#ecfdf3';
        banner.style.color = tipo === 'offline' ? '#9a3412' : '#166534';
        banner.textContent = texto;
    };

    const serializar = () => {
        const datos = {};
        new FormData(form).forEach((valor, nombre) => {
            if (Object.prototype.hasOwnProperty.call(datos, nombre)) {
                if (!Array.isArray(datos[nombre])) {
                    datos[nombre] = [datos[nombre]];
                }
                datos[nombre].push(valor);
            } else {
                datos[nombre] = valor;
            }
        });
        return datos;
    };

    const aplicar = (datos) => {
        Object.keys(datos).forEach((nombre) => {
            const valor = datos[nombre];
            const campos = form.querySelectorAll('[name="' + CSS.escape(nombre) + '"]');
            if (!campos.length) {
                return;
            }
            if (campos[0].type === 'checkbox' || campos[0].type === 'radio') {
                return;
            }
            const lista = Array.isArray(valor) ? valor : [valor];
            campos.forEach((campo, indice) => {
                if (lista[indice] !== undefined) {
                    campo.value = lista[indice];
                }
            });
        });
    };

    const guardar = () => {
        try {
            localStorage.setItem(clave, JSON.stringify({
                cuando: Date.now(),
                datos: serializar(),
            }));
        } catch (error) {
            /* cuota llena */
        }
    };

    try {
        const crudo = localStorage.getItem(clave);
        if (crudo) {
            const paquete = JSON.parse(crudo);
            if (paquete && paquete.datos) {
                aplicar(paquete.datos);
                mostrarBanner('Se restauró un borrador de esta consulta. Revíselo y guarde.', 'ok');
            }
        }
    } catch (error) {
        /* JSON inválido */
    }

    let temporizador;
    form.addEventListener('input', () => {
        window.clearTimeout(temporizador);
        temporizador = window.setTimeout(guardar, 400);
    });
    form.addEventListener('change', guardar);

    form.addEventListener('submit', (evento) => {
        if (!navigator.onLine) {
            evento.preventDefault();
            guardar();
            mostrarBanner('Sin conexión. El borrador quedó en este teléfono. Al volver la red, pulse guardar.', 'offline');
            return;
        }
        try {
            localStorage.removeItem(clave);
        } catch (error) {
            /* ignore */
        }
    });

    window.addEventListener('offline', () => {
        guardar();
        mostrarBanner('Sin conexión. Seguimos guardando un borrador en este teléfono.', 'offline');
    });
    window.addEventListener('online', () => {
        mostrarBanner('Volvió la conexión. Puede guardar ahora.', 'ok');
    });
})();
