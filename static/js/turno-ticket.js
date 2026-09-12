'use strict';

document.getElementById('printTicket')?.addEventListener('click', () => {
    window.print();
});

window.addEventListener('load', () => {
    window.print();
});
