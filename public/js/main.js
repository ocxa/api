document.addEventListener('DOMContentLoaded', () => {
    const appContainer = document.getElementById('app-container');
    const state = {
        loggedIn: false,
        user: null,
    };
    const ICONS = {
        DASHBOARD: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>`,
        SETTINGS: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>`,
        ADMIN: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.286zm0 13.036h.008v.008h-.008v-.008z"></path></svg>`,
    };

    // --- API & Utils ---
    const api = {
        get: (endpoint) => request(endpoint, 'GET'),
                          post: (endpoint, body) => request(endpoint, 'POST', body),
                          put: (endpoint, body) => request(endpoint, 'PUT', body),
                          delete: (endpoint) => request(endpoint, 'DELETE'),
    };
    async function request(endpoint, method, body = null) { /* ... same as your old file ... */ }

    // --- ROUTER & RENDERING ---
    async function router() {
        await checkSession();
        const path = window.location.hash.slice(2) || 'dashboard'; // e.g., 'dashboard', 'settings', 'admin/users'

        if (!state.loggedIn) {
            renderLogin();
            return;
        }

        renderMainLayout();

        if (path.startsWith('admin')) {
            if (state.user?.is_admin) {
                renderAdminView(path.split('/')[1] || 'users');
            } else {
                window.location.hash = '/dashboard';
            }
        } else if (path === 'settings') {
            renderSettingsView();
        } else {
            renderDashboardView();
        }

        updateActiveNavLink(path);
    }

    function renderMainLayout() {
        if (document.querySelector('.main-layout')) return; // Already rendered

        const layoutTemplate = document.getElementById('main-layout-template').content.cloneNode(true);
        appContainer.innerHTML = '';
        appContainer.appendChild(layoutTemplate);

        const sidebarContainer = document.getElementById('sidebar');
        const sidebarTemplate = document.getElementById('sidebar-template').content.cloneNode(true);
        sidebarContainer.appendChild(sidebarTemplate);

        document.getElementById('username-display').textContent = state.user.username;
        document.getElementById('logout-btn').addEventListener('click', handleLogout);

        const nav = document.getElementById('sidebar-nav');
        nav.innerHTML = `
        <a href="#/dashboard">${ICONS.DASHBOARD} Dashboard</a>
        <a href="#/settings">${ICONS.SETTINGS} Settings</a>
        ${state.user?.is_admin ? `<a href="#/admin/users">${ICONS.ADMIN} Admin</a>` : ''}
        `;
    }

    function updateActiveNavLink(path) {
        document.querySelectorAll('.sidebar-nav a').forEach(a => {
            const linkPath = a.getAttribute('href').slice(2);
            if (path.startsWith(linkPath)) {
                a.classList.add('active');
            } else {
                a.classList.remove('active');
            }
        });
    }

    // --- VIEWS ---

    function renderDashboardView() {
        const content = document.getElementById('app-content');
        content.innerHTML = `<h2>Dashboard</h2><div class="url-list"></div>`;
        // ... Load URLs into .url-list ...
    }

    function renderSettingsView() {
        const content = document.getElementById('app-content');
        content.innerHTML = `<h2>Settings</h2>`;
        // ... Render settings content ...
    }

    function renderAdminView(subview) {
        const content = document.getElementById('app-content');
        content.innerHTML = `<h2>Admin Panel</h2>`;
        // ... Render admin content based on subview ...
        updateActiveNavLink(`admin/${subview}`);
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


    window.addEventListener('hashchange', router);
    router();
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
