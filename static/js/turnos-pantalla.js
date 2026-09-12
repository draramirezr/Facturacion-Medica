'use strict';

const queuesElement = document.getElementById('queues');
const updatedElement = document.getElementById('updated');
const feedUrl = document.body.dataset.feedUrl;

function textElement(tag, className, text) {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
}

function renderQueue(queue) {
    const card = document.createElement('section');
    card.className = 'queue';
    card.append(
        textElement('h2', '', queue.medico),
        textElement('div', 'specialty', queue.especialidad),
    );

    const turns = document.createElement('div');
    turns.className = 'turns';
    [
        ['current', 'Turno actual', queue.actual || '—'],
        ['next', 'Siguiente', queue.siguiente || '—'],
    ].forEach(([className, label, number]) => {
        const item = document.createElement('div');
        item.className = className;
        item.append(
            textElement('span', 'turn-label', label),
            textElement('strong', 'turn-number', number),
        );
        turns.append(item);
    });
    card.append(turns);
    return card;
}

async function refreshQueues() {
    try {
        const response = await fetch(feedUrl, {
            headers: {Accept: 'application/json'},
            cache: 'no-store',
        });
        if (!response.ok) {
            throw new Error('Pantalla no disponible');
        }
        const data = await response.json();
        queuesElement.replaceChildren();
        if (!data.colas.length) {
            queuesElement.append(
                textElement('p', 'empty', 'No hay turnos en espera.'),
            );
        } else {
            data.colas.forEach((queue) => {
                queuesElement.append(renderQueue(queue));
            });
        }
        updatedElement.textContent = `Actualizado ${data.actualizado}`;
    } catch (error) {
        updatedElement.textContent = 'Sin conexión';
    }
}

refreshQueues();
window.setInterval(refreshQueues, 4000);
