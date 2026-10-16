const demoPassword = 'authi-demo';
const users = [
  { id: 1, name: 'Jordan Morgan', email: 'admin@authi.local', role: 'Administrator', status: 'Active', initials: 'JM', avatar: 'avatar-amber', admin: true },
  { id: 2, name: 'Alex Lee', email: 'alex@authi.local', role: 'Member', status: 'Active', initials: 'AL', avatar: 'avatar-teal', admin: false },
  { id: 3, name: 'Priya Shah', email: 'priya@authi.local', role: 'Member', status: 'Active', initials: 'PS', avatar: 'avatar-coral', admin: false },
  { id: 4, name: 'Noah Bennett', email: 'noah@authi.local', role: 'Member', status: 'Active', initials: 'NB', avatar: 'avatar-blue', admin: false },
  { id: 5, name: 'Mina Park', email: 'mina@authi.local', role: 'Member', status: 'Active', initials: 'MP', avatar: 'avatar-lilac', admin: false },
];
const applications = [
  { name: 'Outline', detail: 'Team knowledge base', symbol: 'O', tone: 'green', category: 'Documentation', address: 'outline.harbor.test' },
  { name: 'Grafana', detail: 'Metrics & observability', symbol: 'G', tone: 'coral', category: 'Monitoring', address: 'metrics.harbor.test' },
  { name: 'Forgejo', detail: 'Code, issues & reviews', symbol: 'F', tone: 'blue', category: 'Development', address: 'code.harbor.test' },
  { name: 'Paperless', detail: 'Documents & records', symbol: 'P', tone: 'yellow', category: 'Operations', address: 'docs.harbor.test' },
  { name: 'Immich', detail: 'Shared photo library', symbol: 'I', tone: 'lilac', category: 'Personal', address: 'photos.harbor.test' },
];
const state = { user: null, page: 'home', addedUsers: [], search: '', roleFilter: 'all', toastTimer: null };
const loginScreen = document.querySelector('#loginScreen');
const appShell = document.querySelector('#appShell');
const loginForm = document.querySelector('#loginForm');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const loginError = document.querySelector('#loginError');
const pageContent = document.querySelector('#pageContent');
const modalBackdrop = document.querySelector('#modalBackdrop');
const modalContent = document.querySelector('#modalContent');
const toast = document.querySelector('#toast');

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function accountFor(email) {
  if (email === 'admin@authi.local') return users[0];
  if (email === 'alex@authi.local') return users[1];
  return null;
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { toast.hidden = true; }, 2800);
}

function appCard(app) {
  return `<article class="application-card">
    <div class="app-card-top"><span class="app-icon app-icon-${app.tone}">${escapeHtml(app.symbol)}</span><button class="app-card-arrow" type="button" data-launch="${escapeHtml(app.name)}" aria-label="Open ${escapeHtml(app.name)}">&#8599;</button></div>
    <h3>${escapeHtml(app.name)}</h3><p>${escapeHtml(app.detail)}</p>
    <div class="app-card-foot"><span>${escapeHtml(app.category)}</span><span class="access-pill">Connected</span></div>
  </article>`;
}

function heading(kicker, title, detail, action = '') {
  return `<div class="page-heading"><div><p class="eyebrow">${kicker}</p><h1>${title}</h1><p>${detail}</p></div>${action ? `<div class="heading-actions">${action}</div>` : ''}</div>`;
}

function homePage() {
  const firstName = escapeHtml(state.user.name.split(' ')[0]);
  return `${heading('YOUR WORKSPACE', `Good morning, ${firstName}`, 'Your connected tools, ready when you are.')}
    <section class="welcome-band"><div class="welcome-copy"><p class="eyebrow">HARBOR HOUSE WORKSPACE</p><h2>Everything you need.<br>One secure place.</h2><p>Signed in as ${escapeHtml(state.user.email)}</p></div><span class="welcome-stamp">HH / 01</span></section>
    <div class="section-head"><h2>Your applications</h2><button class="text-link" type="button" data-page="apps">View all <span aria-hidden="true">&rarr;</span></button></div>
    <div class="application-grid">${applications.slice(0, 3).map(appCard).join('')}</div>
    <div class="home-lower">
      <section class="surface-panel"><div class="surface-panel-heading"><h2>Recent activity</h2><span>JUST FOR YOU</span></div><div class="activity-list">
        <div class="activity-row"><span class="activity-icon">&#10003;</span><span class="activity-copy"><strong>Signed in successfully</strong><small>Local account &#183; this browser</small></span><span class="activity-time">NOW</span></div>
        <div class="activity-row"><span class="activity-icon">&#8599;</span><span class="activity-copy"><strong>Workspace access verified</strong><small>Harbor House &#183; 3 applications</small></span><span class="activity-time">TODAY</span></div>
      </div></section>
      <section class="surface-panel"><div class="surface-panel-heading"><h2>Your team</h2><span>HARBOR HOUSE</span></div><div class="membership-content"><p>Your account is part of the Harbor House workspace.</p><div class="member-stack"><span class="account-avatar avatar-amber">JM</span><span class="account-avatar avatar-teal">AL</span><span class="account-avatar avatar-coral">PS</span><span class="account-avatar avatar-blue">NB</span><span class="member-total">+8 members</span></div></div></section>
    </div>`;
}

function appsPage() {
  return `${heading('YOUR ACCESS', 'My applications', 'Tools connected to your Harbor House account.')}
    <div class="application-grid">${applications.map(appCard).join('')}</div>
    <p class="demo-footnote">These app links are illustrative. No external service is opened in this preview.</p>`;
}

function avatar(user) {
  return `<span class="account-avatar ${user.avatar}">${escapeHtml(user.initials)}</span>`;
}

function shortUserRow(user) {
  return `<tr><td><div class="user-cell">${avatar(user)}<span><strong>${escapeHtml(user.name)}</strong><small>${escapeHtml(user.email)}</small></span></div></td><td><span class="role-tag ${user.admin ? 'admin' : ''}">${escapeHtml(user.role)}</span></td><td><span class="status-tag">${escapeHtml(user.status)}</span></td></tr>`;
}

function quickApps() {
  return applications.slice(0, 3).map((app) => `<div class="quick-row"><span class="app-icon app-icon-${app.tone}">${escapeHtml(app.symbol)}</span><span class="quick-row-copy"><strong>${escapeHtml(app.name)}</strong><small>${escapeHtml(app.category)}</small></span><span class="quick-state">Active</span></div>`).join('');
}

function adminPage() {
  const visibleUsers = users.slice(0, 4);
  return `${heading('WORKSPACE ADMIN', 'Workspace overview', 'A quick look at people and connected applications.', '<button class="button button-outline button-compact" data-page="users" type="button">Manage users</button><button class="button button-primary button-compact" data-invite type="button">+ Invite user</button>')}
    <div class="stats-grid">
      <article class="stat-card"><span class="stat-label">Active users</span><div class="stat-value-row"><strong class="stat-value">${12 + state.addedUsers.length}</strong><span class="stat-change">+2 this month</span></div><div class="stat-footnote">Across 3 access groups</div></article>
      <article class="stat-card"><span class="stat-label">Connected apps</span><div class="stat-value-row"><strong class="stat-value">${applications.length}</strong><span class="stat-change">All healthy</span></div><div class="stat-footnote">OIDC &amp; forward-auth</div></article>
      <article class="stat-card"><span class="stat-label">Identity sources</span><div class="stat-value-row"><strong class="stat-value">2</strong><span class="stat-change">Connected</span></div><div class="stat-footnote">Local directory + Entra ID</div></article>
    </div>
    <div class="admin-grid"><section class="surface-panel table-panel"><div class="table-toolbar"><h2>People</h2><button class="text-link" data-page="users" type="button">All users &rarr;</button></div><table class="data-table"><thead><tr><th>USER</th><th>ROLE</th><th>STATUS</th></tr></thead><tbody>${visibleUsers.map(shortUserRow).join('')}</tbody></table></section>
    <section class="surface-panel quick-panel"><h2>Connected applications</h2>${quickApps()}</section></div>`;
}

function userPage() {
  const query = state.search.trim().toLowerCase();
  const allUsers = [...users, ...state.addedUsers];
  const filtered = allUsers.filter((user) => {
    const matchesSearch = `${user.name} ${user.email} ${user.role}`.toLowerCase().includes(query);
    const matchesRole = state.roleFilter === 'all' || (state.roleFilter === 'admin' ? user.admin : user.status === 'Active');
    return matchesSearch && matchesRole;
  });
  return `${heading('WORKSPACE ADMIN', 'People', 'Manage who can sign in to Harbor House.', '<button class="button button-primary button-compact" data-invite type="button">+ Invite user</button>')}
    <div class="filter-bar"><button class="filter-chip ${state.roleFilter === 'all' ? 'is-active' : ''}" type="button" data-filter="all">All users <span>${allUsers.length}</span></button><button class="filter-chip ${state.roleFilter === 'admin' ? 'is-active' : ''}" type="button" data-filter="admin">Admins <span>1</span></button><button class="filter-chip ${state.roleFilter === 'active' ? 'is-active' : ''}" type="button" data-filter="active">Active <span>${allUsers.length}</span></button></div>
    <section class="surface-panel full-table-panel"><div class="table-toolbar"><h2>Workspace members</h2><label class="search-wrap"><span class="search-mark" aria-hidden="true">&#9906;</span><input class="search-input" id="userSearch" type="search" placeholder="Search people" value="${escapeHtml(state.search)}" aria-label="Search people"></label><span class="toolbar-count">${filtered.length} shown</span></div><table class="data-table"><thead><tr><th>USER</th><th>ROLE</th><th>STATUS</th><th>LAST SIGN-IN</th></tr></thead><tbody>${filtered.map((user) => `<tr><td><div class="user-cell">${avatar(user)}<span><strong>${escapeHtml(user.name)}</strong><small>${escapeHtml(user.email)}</small></span></div></td><td><span class="role-tag ${user.admin ? 'admin' : ''}">${escapeHtml(user.role)}</span></td><td><span class="status-tag">${escapeHtml(user.status)}</span></td><td>${user.id === 1 ? 'Just now' : 'Today'}</td></tr>`).join('') || '<tr><td colspan="4"><div class="empty-state">No people match that search.</div></td></tr>'}</tbody></table></section>
    <p class="demo-footnote">Changes in this view exist only until this page is reloaded.</p>`;
}

function applicationAdminPage() {
  const cards = applications.map((app) => `<article class="admin-app-card"><div class="admin-app-head"><span class="app-icon app-icon-${app.tone}">${escapeHtml(app.symbol)}</span><span><h3>${escapeHtml(app.name)}</h3><p>${escapeHtml(app.detail)}</p></span><span class="quick-state">Active</span></div><div class="admin-app-meta"><span>TYPE<strong>${escapeHtml(app.category)}</strong></span><span>HOST<strong>${escapeHtml(app.address)}</strong></span></div></article>`).join('');
  return `${heading('WORKSPACE ADMIN', 'Applications', 'Services available to members of this workspace.', '<button class="button button-primary button-compact" data-connect type="button">+ Connect application</button>')}
    <div class="stats-grid"><article class="stat-card"><span class="stat-label">Connected</span><div class="stat-value-row"><strong class="stat-value">${applications.length}</strong><span class="stat-change">Healthy</span></div><div class="stat-footnote">All configured applications</div></article><article class="stat-card"><span class="stat-label">Sign-in method</span><div class="stat-value-row"><strong class="stat-value stat-value-text">OIDC</strong><span class="stat-change">Encrypted</span></div><div class="stat-footnote">Secrets are hidden in this preview</div></article><article class="stat-card"><span class="stat-label">Member access</span><div class="stat-value-row"><strong class="stat-value">12</strong><span class="stat-change">Scoped</span></div><div class="stat-footnote">Access follows workspace policy</div></article></div>
    <div class="section-head"><h2>All applications</h2><span class="subtle">${applications.length} configured</span></div><div class="application-admin-grid">${cards}</div>`;
}

const pages = { home: homePage, apps: appsPage, admin: adminPage, users: userPage, applications: applicationAdminPage };
const pageNames = { home: 'Overview', apps: 'My applications', admin: 'Admin overview', users: 'Users', applications: 'Applications' };

function renderPage() {
  if (!pages[state.page]) state.page = 'home';
  document.querySelector('#pageCrumb').textContent = pageNames[state.page];
  pageContent.innerHTML = pages[state.page]();
  document.querySelectorAll('.nav-link').forEach((link) => link.classList.toggle('is-active', link.dataset.page === state.page));
  document.querySelector('#sidebar').classList.remove('is-open');
}

function signIn(user) {
  state.user = user;
  state.page = 'home';
  loginScreen.hidden = true;
  appShell.hidden = false;
  document.querySelector('#adminNav').hidden = !user.admin;
  document.querySelector('#profileAvatar').className = `account-avatar ${user.avatar}`;
  document.querySelector('#profileAvatar').textContent = user.initials;
  document.querySelector('#profileName').textContent = user.name;
  document.querySelector('#profileRole').textContent = user.role;
  renderPage();
}

function signOut() {
  state.user = null;
  state.page = 'home';
  appShell.hidden = true;
  loginScreen.hidden = false;
  loginForm.reset();
  loginError.hidden = true;
  emailInput.focus();
}

function openModal(content) {
  modalContent.innerHTML = content;
  modalBackdrop.hidden = false;
  modalContent.querySelector('input')?.focus();
}

function closeModal() {
  modalBackdrop.hidden = true;
  modalContent.innerHTML = '';
}

function inviteModal() {
  openModal(`<p class="eyebrow">HARBOR HOUSE</p><h2 id="modalTitle">Invite a teammate</h2><p>Add a sample person to this local preview. No invitation will be sent.</p><form id="inviteForm"><label for="inviteName">Full name</label><input id="inviteName" name="name" placeholder="Taylor Reed" required><label for="inviteEmail">Email address</label><input id="inviteEmail" name="email" type="email" placeholder="taylor@example.com" required><div class="modal-actions"><button class="button button-outline button-compact" type="button" data-close-modal>Cancel</button><button class="button button-primary button-compact" type="submit">Add to preview</button></div></form><p class="demo-footnote">This sample user disappears when you reload.</p>`);
}

function createInvite(form) {
  const data = new FormData(form);
  const name = String(data.get('name') ?? '').trim();
  const email = String(data.get('email') ?? '').trim().toLowerCase();
  if (!name || !email.includes('@')) return;
  if ([...users, ...state.addedUsers].some((user) => user.email.toLowerCase() === email)) {
    showToast('That email is already in the sample workspace.');
    return;
  }
  const initials = name.split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase();
  state.addedUsers.push({ id: Date.now(), name, email, role: 'Member', status: 'Active', initials, avatar: 'avatar-lilac', admin: false });
  closeModal();
  renderPage();
  showToast(`${name} added to this preview.`);
}

loginForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const account = accountFor(emailInput.value.trim().toLowerCase());
  if (!account || passwordInput.value !== demoPassword) {
    loginError.textContent = 'That sample sign-in did not match. Choose an account below and use the preview password.';
    loginError.hidden = false;
    passwordInput.setAttribute('aria-invalid', 'true');
    return;
  }
  loginError.hidden = true;
  passwordInput.removeAttribute('aria-invalid');
  signIn(account);
});

document.querySelectorAll('[data-email]').forEach((button) => button.addEventListener('click', () => {
  emailInput.value = button.dataset.email;
  passwordInput.value = demoPassword;
  loginError.hidden = true;
  loginForm.requestSubmit();
}));

document.querySelector('#togglePassword').addEventListener('click', (event) => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} password`);
});

document.querySelector('#profileButton').addEventListener('click', signOut);
document.querySelector('#helpButton').addEventListener('click', () => showToast('This is a local preview. Nothing is saved or sent to Auth.i.'));
document.querySelector('#mobileMenu').addEventListener('click', () => document.querySelector('#sidebar').classList.toggle('is-open'));
document.querySelector('#modalClose').addEventListener('click', closeModal);
modalBackdrop.addEventListener('click', (event) => { if (event.target === modalBackdrop) closeModal(); });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeModal(); });

document.addEventListener('click', (event) => {
  const pageButton = event.target.closest('[data-page]');
  if (pageButton && state.user) {
    const page = pageButton.dataset.page;
    if ((page === 'admin' || page === 'users' || page === 'applications') && !state.user.admin) {
      showToast('Admin preview is available with the administrator sample account.');
      return;
    }
    state.page = page;
    renderPage();
    return;
  }
  if (event.target.closest('[data-invite]') && state.user?.admin) { inviteModal(); return; }
  if (event.target.closest('[data-close-modal]')) { closeModal(); return; }
  const launch = event.target.closest('[data-launch]');
  if (launch) { showToast(`${launch.dataset.launch} is a sample app link; no external service was opened.`); return; }
  if (event.target.closest('[data-connect]')) showToast('Application setup is not connected in this preview.');
});

document.addEventListener('submit', (event) => {
  if (event.target.id === 'inviteForm') {
    event.preventDefault();
    createInvite(event.target);
  }
});

document.addEventListener('input', (event) => {
  if (event.target.id === 'userSearch') {
    const cursor = event.target.selectionStart;
    state.search = event.target.value;
    renderPage();
    const nextSearch = document.querySelector('#userSearch');
    nextSearch.focus();
    nextSearch.setSelectionRange(cursor, cursor);
  }
});

document.addEventListener('click', (event) => {
  const filter = event.target.closest('[data-filter]');
  if (!filter || state.page !== 'users') return;
  state.roleFilter = filter.dataset.filter;
  renderPage();
});
