// js/main.js
document.addEventListener('DOMContentLoaded', () => {
    const app = document.getElementById('app');
    const mainNav = document.getElementById('main-nav');
    let state = {
        loggedIn: false,
        user: null
    };

    // --- API HELPER ---
    const api = {
        get: (endpoint) => request(endpoint, 'GET'),
                          post: (endpoint, body) => request(endpoint, 'POST', body),
                          put: (endpoint, body) => request(endpoint, 'PUT', body),
                          delete: (endpoint) => request(endpoint, 'DELETE'),
    };

    async function request(endpoint, method, body = null) {
        const headers = { 'Content-Type': 'application/json' };
        const config = {
            method,
            headers,
        };
        if (body) {
            config.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(`/api${endpoint}`, config);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            if (response.status === 204 || response.headers.get('content-length') === '0') {
                return null; // Handle no-content responses
            }
            return await response.json();
        } catch (error) {
            console.error('API Error:', error.message);
            showNotification(error.message, 'error');
            throw error;
        }
    }

    // --- NOTIFICATIONS ---
    function showNotification(message, type = 'success') {
        const notif = document.createElement('div');
        notif.className = `notification ${type}`;
        notif.textContent = message;
        document.body.appendChild(notif);
        setTimeout(() => {
            notif.remove();
        }, 3000);
    }

    // --- ROUTER & RENDERING ---
    async function router() {
        showSpinner();
        await checkSession();
        const path = window.location.hash.slice(1) || '/';

        updateNav();

        if (!state.loggedIn) {
            renderLogin();
            return;
        }

        if (path.startsWith('/admin')) {
            if (state.user && state.user.is_admin) {
                renderAdmin(path.split('/')[2]);
            } else {
                window.location.hash = '/'; // Redirect non-admins
            }
        } else if (path === '/settings') {
            renderSettings();
        } else {
            renderDashboard();
        }
    }

    function updateNav() {
        mainNav.innerHTML = '';
        if (state.loggedIn) {
            mainNav.innerHTML = `
            <a href="#" class="nav-link ${window.location.hash === '#' || window.location.hash === '' ? 'active' : ''}">Dashboard</a>
            <a href="#/settings" class="nav-link ${window.location.hash === '#/settings' ? 'active' : ''}">Settings</a>
            `;
            if (state.user.is_admin) {
                mainNav.innerHTML += `<a href="#/admin" class="nav-link ${window.location.hash.startsWith('#/admin') ? 'active' : ''}">Admin</a>`;
            }
            const logoutButton = document.createElement('button');
            logoutButton.textContent = 'Logout';
            logoutButton.onclick = handleLogout;
            mainNav.appendChild(logoutButton);
        }
    }

    async function checkSession() {
        try {
            const sessionData = await api.get('/auth/session');
            state.loggedIn = sessionData.loggedIn;
            state.user = sessionData.user;
        } catch (e) {
            state.loggedIn = false;
            state.user = null;
        }
    }

    function showSpinner() {
        app.innerHTML = `<div class="spinner-container"><div class="spinner"></div></div>`;
    }

    function renderTemplate(templateId, target = app) {
        const template = document.getElementById(templateId);
        target.innerHTML = '';
        target.appendChild(template.content.cloneNode(true));
    }

    // --- LOGIN/REGISTER VIEW ---
    function renderLogin() {
        renderTemplate('login-template');

        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        const tabs = document.querySelectorAll('.tab-button');
        const messageEl = document.getElementById('auth-message');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                document.querySelectorAll('.auth-form').forEach(form => form.classList.remove('active'));
                document.getElementById(`${tab.dataset.tab}-form`).classList.add('active');
                messageEl.textContent = '';
            });
        });

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            try {
                await api.post('/auth/login', { username, password });
                window.location.hash = '/';
                router();
            } catch (error) {
                messageEl.textContent = error.message;
                messageEl.className = 'message error';
            }
        });

        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;
            const inviteCode = document.getElementById('invite-code').value;
            try {
                const result = await api.post('/auth/register', { username, password, inviteCode });
                messageEl.textContent = result.message + '. Please login.';
                messageEl.className = 'message success';
                document.querySelector('[data-tab="login"]').click(); // Switch to login tab
                registerForm.reset();
            } catch (error) {
                messageEl.textContent = error.message;
                messageEl.className = 'message error';
            }
        });
    }

    async function handleLogout() {
        await api.post('/auth/logout');
        state.loggedIn = false;
        state.user = null;
        window.location.hash = '';
        router();
    }

    // --- DASHBOARD VIEW ---
    async function renderDashboard() {
        renderTemplate('dashboard-template');
        const container = document.getElementById('url-list-container');
        try {
            const urls = await api.get('/urls');
            if (urls.length === 0) {
                container.innerHTML = `<p>You haven't created any shortened URLs yet.</p>`;
                return;
            }
            container.innerHTML = ''; // Clear spinner/message
            urls.forEach(url => container.appendChild(createUrlCard(url)));
        } catch (error) {
            container.innerHTML = `<p class="error-message">Could not load your URLs.</p>`;
        }
    }

    function createUrlCard(url) {
        const card = document.createElement('div');
        card.className = 'card url-card';
        card.dataset.id = url.id;

        const shortUrl = `${window.location.origin}/r/${url.short_code}`;

        card.innerHTML = `
        <div class="url-info">
        <p class="short-url"><a href="${shortUrl}" target="_blank">${shortUrl.replace('https://', '').replace('http://', '')}</a></p>
        <p class="original-url">${url.original_url}</p>
        </div>
        <div class="url-stats">
        <span>Clicks: ${url.clicks}</span>
        <span>Expires: ${url.expires_at ? new Date(url.expires_at).toLocaleString() : 'Never'}</span>
        </div>
        <div class="url-actions">
        <button class="copy-btn">Copy</button>
        <button class="edit-btn secondary">Edit</button>
        <button class="delete-btn danger">Delete</button>
        </div>
        `;

        card.querySelector('.copy-btn').addEventListener('click', () => {
            navigator.clipboard.writeText(shortUrl);
            showNotification('Copied to clipboard!');
        });

        card.querySelector('.delete-btn').addEventListener('click', async () => {
            if(confirm('Are you sure you want to delete this URL?')) {
                try {
                    await api.delete(`/urls/${url.id}`);
                    card.remove();
                    showNotification('URL deleted.');
                } catch(e) {/* already handled by api helper */}
            }
        });

        // Add edit logic later
        // card.querySelector('.edit-btn').addEventListener('click', () => { ... });

        return card;
    }

    // --- SETTINGS VIEW ---
    async function renderSettings() {
        renderTemplate('settings-template');

        // Change Password Logic
        const passwordForm = document.getElementById('change-password-form');
        const passwordMessage = document.getElementById('password-message');
        passwordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            try {
                const result = await api.post('/user/change-password', { currentPassword, newPassword });
                passwordMessage.textContent = result.message;
                passwordMessage.className = 'message success';
                passwordForm.reset();
            } catch(error) {
                passwordMessage.textContent = error.message;
                passwordMessage.className = 'message error';
            }
        });

        // API Key Logic
        const apiKeyInfo = document.getElementById('api-key-info');
        const apiKeyMessage = document.getElementById('api-key-message');
        const generateBtn = document.getElementById('generate-key-btn');
        const deleteBtn = document.getElementById('delete-key-btn');

        async function loadApiKey() {
            try {
                const keyData = await api.get('/keys/info');
                if (keyData && keyData.key_preview) {
                    apiKeyInfo.innerHTML = `
                    <p><strong>Key Preview:</strong> ${keyData.key_preview}</p>
                    <p><strong>Created:</strong> ${new Date(keyData.created_at).toLocaleString()}</p>
                    <p><strong>Last Used:</strong> ${keyData.last_used ? new Date(keyData.last_used).toLocaleString() : 'Never'}</p>
                    `;
                    deleteBtn.style.display = 'inline-block';
                    generateBtn.textContent = 'Generate New Key (Replaces Old One)';
                } else {
                    apiKeyInfo.innerHTML = '<p>No API key has been generated yet.</p>';
                    deleteBtn.style.display = 'none';
                    generateBtn.textContent = 'Generate API Key';
                }
            } catch (e) {
                apiKeyInfo.innerHTML = '<p class="message error">Could not load API key information.</p>';
            }
        }

        generateBtn.addEventListener('click', async () => {
            if (confirm('Are you sure? Any existing key will be invalidated.')) {
                try {
                    const result = await api.post('/keys/generate');
                    apiKeyMessage.className = 'message success';
                    apiKeyMessage.innerHTML = `New key generated! Please copy it, this is the only time it will be shown.<br><strong>${result.apiKey}</strong>`;
                    loadApiKey();
                } catch(e) {/* handled */}
            }
        });

        deleteBtn.addEventListener('click', async () => {
            if(confirm('Are you sure you want to delete your API key?')) {
                try {
                    await api.delete(`/keys/${state.user.id}`); // This API expects admin, let's change it
                    // TODO: The backend needs a non-admin DELETE route for own key
                    showNotification('API Key deleted.', 'success');
                    loadApiKey();
                } catch (e) {/* handled */}
            }
        });

        loadApiKey();
    }

    // --- ADMIN VIEW ---
    async function renderAdmin(subview = 'users') {
        renderTemplate('admin-template');
        document.querySelectorAll('.admin-nav-link').forEach(link => {
            link.classList.remove('active');
            if(link.dataset.view === subview) {
                link.classList.add('active');
            }
        });

        const content = document.getElementById('admin-content');
        content.innerHTML = `<div class="spinner-container"><div class="spinner"></div></div>`;

        switch(subview) {
            case 'urls':
                // await renderAdminUrls(content);
                content.innerHTML = 'Admin URLs view not implemented yet.';
                break;
            case 'invites':
                // await renderAdminInvites(content);
                content.innerHTML = 'Admin Invites view not implemented yet.';
                break;
            case 'ips':
                // await renderAdminIps(content);
                content.innerHTML = 'Admin IPs view not implemented yet.';
                break;
            case 'users':
            default:
                await renderAdminUsers(content);
                break;
        }
    }

    async function renderAdminUsers(container) {
        try {
            const users = await api.get('/admin/users');
            let rows = users.map(user => `
            <tr>
            <td>${user.id}</td>
            <td>${user.username}</td>
            <td>${user.ip_address || 'N/A'}</td>
            <td>${user.is_admin ? 'Yes' : 'No'}</td>
            <td>
            <button class="action-btn toggle-block-btn" data-id="${user.id}" data-blocked="${user.is_blocked}">
            ${user.is_blocked ? 'Unblock' : 'Block'}
            </button>
            </td>
            <td>
            <button class="action-btn toggle-post-btn" data-id="${user.id}" data-can-post="${user.can_post}">
            ${user.can_post ? 'Disable' : 'Enable'}
            </button>
            </td>
            <td>
            <button class="action-btn danger delete-user-btn" data-id="${user.id}">Delete</button>
            </td>
            </tr>
            `).join('');

            container.innerHTML = `
            <h3>Manage Users</h3>
            <div class="table-container">
            <table>
            <thead><tr><th>ID</th><th>Username</th><th>Last IP</th><th>Admin</th><th>Status</th><th>Posting</th><th>Actions</th></tr></thead>
            <tbody>${rows}</tbody>
            </table>
            </div>
            `;
            // Add event listeners for all the buttons
        } catch (error) {
            container.innerHTML = '<p class="message error">Failed to load users.</p>';
        }
    }


    // --- INITIALIZATION ---
    window.addEventListener('hashchange', router);
    router(); // Initial call
});

// A proper notification would be better than an alert.
// Adding a simple one in CSS.
const style = document.createElement('style');
style.textContent = `
.notification {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    padding: 1rem 2rem;
    border-radius: 6px;
    color: white;
    font-weight: 500;
    z-index: 1000;
    opacity: 0;
    animation: fadeinout 3s ease-in-out;
}
.notification.success { background-color: #4CAF50; }
.notification.error { background-color: #f44336; }

@keyframes fadeinout {
    0%, 100% { opacity: 0; bottom: 0px; }
    10%, 90% { opacity: 1; bottom: 20px; }
}
`;
document.head.appendChild(style);
