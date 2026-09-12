(function () {
    'use strict';

    const panel = document.getElementById('arsChatPanel');
    if (!panel) {
        return;
    }

    const toggle = document.getElementById('arsChatToggle');
    const closeButton = document.getElementById('arsChatClose');
    const overlay = document.getElementById('arsChatOverlay');
    const contactsElement = document.getElementById('arsChatContacts');
    const search = document.getElementById('arsChatSearch');
    const header = document.getElementById('arsChatConversationHeader');
    const messagesElement = document.getElementById('arsChatMessages');
    const form = document.getElementById('arsChatForm');
    const body = document.getElementById('arsChatBody');
    const feedback = document.getElementById('arsChatFeedback');
    const unreadBadge = document.getElementById('arsChatUnread');
    const currentUserId = Number(panel.dataset.currentUserId);

    let users = [];
    let conversations = new Map();
    let selectedUser = null;
    let lastMessageId = 0;
    let loadingMessages = false;

    const requestJson = async (url, options = {}) => {
        const response = await fetch(url, {
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                ...(options.body ? {'Content-Type': 'application/json'} : {}),
                ...(options.headers || {})
            },
            ...options
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(payload.error || 'No se pudo completar la solicitud');
        }
        return payload;
    };

    const initials = (name) => String(name || '')
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((part) => part.charAt(0).toUpperCase())
        .join('');

    const formatTime = (value) => {
        if (!value) {
            return '';
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return new Intl.DateTimeFormat('es-DO', {
            day: '2-digit',
            month: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        }).format(date);
    };

    const setFeedback = (message = '') => {
        feedback.textContent = message;
    };

    const updateUnreadBadge = (total) => {
        const count = Number(total) || 0;
        unreadBadge.hidden = count === 0;
        unreadBadge.textContent = count > 99 ? '99+' : String(count);
        toggle.setAttribute(
            'aria-label',
            count ? `Abrir mensajería, ${count} sin leer` : 'Abrir mensajería'
        );
    };

    const renderContacts = () => {
        const term = search.value.trim().toLocaleLowerCase('es');
        const filtered = users.filter((user) => (
            `${user.nombre} ${user.perfil}`.toLocaleLowerCase('es').includes(term)
        ));
        contactsElement.replaceChildren();
        if (!filtered.length) {
            const empty = document.createElement('div');
            empty.className = 'ars-chat-state';
            empty.textContent = users.length
                ? 'No hay coincidencias.'
                : 'No hay otros usuarios activos.';
            contactsElement.appendChild(empty);
            return;
        }

        filtered.forEach((user) => {
            const conversation = conversations.get(Number(user.id)) || {};
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'ars-chat-contact';
            button.classList.toggle(
                'active',
                Boolean(selectedUser && Number(selectedUser.id) === Number(user.id))
            );
            button.dataset.userId = user.id;

            const avatar = document.createElement('span');
            avatar.className = 'ars-chat-avatar';
            avatar.textContent = initials(user.nombre);

            const copy = document.createElement('span');
            copy.className = 'ars-chat-contact-copy';
            const name = document.createElement('strong');
            name.textContent = user.nombre;
            const detail = document.createElement('small');
            detail.textContent = conversation.ultimo_mensaje || user.perfil;
            copy.append(name, detail);
            button.append(avatar, copy);

            const unread = Number(conversation.no_leidos) || 0;
            if (unread) {
                const badge = document.createElement('span');
                badge.className = 'ars-chat-contact-badge';
                badge.textContent = unread > 99 ? '99+' : String(unread);
                button.appendChild(badge);
            }
            button.addEventListener('click', () => selectUser(user));
            contactsElement.appendChild(button);
        });
    };

    const loadContacts = async () => {
        try {
            const [usersPayload, conversationsPayload] = await Promise.all([
                requestJson('/api/mensajeria/usuarios'),
                requestJson('/api/mensajeria/conversaciones')
            ]);
            users = usersPayload.usuarios || [];
            conversations = new Map(
                (conversationsPayload.conversaciones || []).map(
                    (conversation) => [Number(conversation.usuario_id), conversation]
                )
            );
            contactsElement.className = 'ars-chat-contact-list';
            renderContacts();
        } catch (error) {
            contactsElement.textContent = error.message;
            contactsElement.className = 'ars-chat-contact-list ars-chat-state';
        }
    };

    const createMessageElement = (message) => {
        const wrapper = document.createElement('div');
        const sent = Number(message.remitente_id) === currentUserId;
        wrapper.className = `ars-chat-message ${sent ? 'sent' : 'received'}`;
        wrapper.dataset.messageId = message.id;
        const bubble = document.createElement('div');
        bubble.className = 'ars-chat-bubble';
        const text = document.createElement('span');
        text.textContent = message.cuerpo;
        const time = document.createElement('small');
        time.className = 'ars-chat-time';
        time.textContent = formatTime(message.created_at);
        bubble.append(text, time);
        wrapper.appendChild(bubble);
        return wrapper;
    };

    const appendMessages = (messages, reset) => {
        if (reset) {
            messagesElement.replaceChildren();
        }
        messages.forEach((message) => {
            if (messagesElement.querySelector(`[data-message-id="${message.id}"]`)) {
                return;
            }
            messagesElement.appendChild(createMessageElement(message));
            lastMessageId = Math.max(lastMessageId, Number(message.id));
        });
        if (reset && !messages.length) {
            const empty = document.createElement('div');
            empty.className = 'ars-chat-empty';
            empty.textContent = 'Aún no hay mensajes. Inicia la conversación.';
            messagesElement.appendChild(empty);
        }
        if (messages.length) {
            messagesElement.scrollTop = messagesElement.scrollHeight;
        }
    };

    const markRead = async (messages) => {
        const received = messages.filter(
            (message) => (
                Number(message.destinatario_id) === currentUserId
                && !message.leido_at
            )
        );
        if (!received.length || !selectedUser) {
            return;
        }
        const highestId = Math.max(...received.map((message) => Number(message.id)));
        await requestJson('/api/mensajeria/leer', {
            method: 'POST',
            body: JSON.stringify({
                usuario_id: Number(selectedUser.id),
                hasta_id: highestId
            })
        });
        await Promise.all([loadUnread(), loadContacts()]);
    };

    const loadMessages = async (reset = false) => {
        if (!selectedUser || loadingMessages) {
            return;
        }
        loadingMessages = true;
        try {
            const after = reset ? 0 : lastMessageId;
            const payload = await requestJson(
                `/api/mensajeria/mensajes/${selectedUser.id}?after_id=${after}`
            );
            const messages = payload.mensajes || [];
            appendMessages(messages, reset);
            await markRead(messages);
        } catch (error) {
            setFeedback(error.message);
        } finally {
            loadingMessages = false;
        }
    };

    const selectUser = async (user) => {
        selectedUser = user;
        lastMessageId = 0;
        setFeedback();
        header.replaceChildren();
        const name = document.createElement('strong');
        name.textContent = user.nombre;
        const profile = document.createElement('small');
        profile.textContent = user.perfil;
        header.append(name, profile);
        form.hidden = false;
        messagesElement.innerHTML = '<div class="ars-chat-state">Cargando mensajes…</div>';
        renderContacts();
        await loadMessages(true);
        body.focus();
    };

    const loadUnread = async () => {
        try {
            const payload = await requestJson('/api/mensajeria/no-leidos');
            updateUnreadBadge(payload.total);
        } catch (error) {
            updateUnreadBadge(0);
        }
    };

    const openPanel = async () => {
        overlay.hidden = false;
        panel.classList.add('open');
        panel.setAttribute('aria-hidden', 'false');
        toggle.setAttribute('aria-expanded', 'true');
        await Promise.all([loadContacts(), loadUnread()]);
        search.focus();
    };

    const closePanel = () => {
        panel.classList.remove('open');
        panel.setAttribute('aria-hidden', 'true');
        toggle.setAttribute('aria-expanded', 'false');
        overlay.hidden = true;
        toggle.focus();
    };

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const messageBody = body.value.trim();
        if (!selectedUser || !messageBody) {
            setFeedback('Escribe un mensaje antes de enviarlo.');
            return;
        }
        const submitButton = form.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        setFeedback();
        try {
            const payload = await requestJson('/api/mensajeria/mensajes', {
                method: 'POST',
                body: JSON.stringify({
                    destinatario_id: Number(selectedUser.id),
                    cuerpo: messageBody
                })
            });
            const empty = messagesElement.querySelector('.ars-chat-empty');
            empty?.remove();
            appendMessages([payload.mensaje], false);
            body.value = '';
            await loadContacts();
        } catch (error) {
            setFeedback(error.message);
        } finally {
            submitButton.disabled = false;
            body.focus();
        }
    });

    toggle.addEventListener('click', openPanel);
    closeButton.addEventListener('click', closePanel);
    overlay.addEventListener('click', closePanel);
    search.addEventListener('input', renderContacts);
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && panel.classList.contains('open')) {
            closePanel();
        }
    });
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            loadUnread();
            if (panel.classList.contains('open')) {
                loadContacts();
                loadMessages();
            }
        }
    });

    loadUnread();
    window.setInterval(loadUnread, 30000);
    window.setInterval(() => {
        if (panel.classList.contains('open')) {
            loadMessages();
        }
    }, 5000);
}());
