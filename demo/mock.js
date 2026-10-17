const demoPassword = 'keystone-demo';
const baseUrl = 'https://keystone.harbor.test';
const issuer = `${baseUrl}/oidc`;
const tones = ['blue', 'green', 'amber', 'violet', 'rose', 'slate'];

const users = [
  { name: 'Jordan Morgan', email: 'jordan@harbor.test', admin: true, status: 'Active', mfa: 'Passkey', lastSeen: 'Just now', tone: 'blue' },
  { name: 'Alex Lee', email: 'alex@harbor.test', admin: false, status: 'Active', mfa: 'Passkey', lastSeen: 'Today, 08:41', tone: 'green' },
  { name: 'Priya Shah', email: 'priya@harbor.test', admin: false, status: 'Active', mfa: 'Authenticator app', lastSeen: 'Yesterday', tone: 'violet' },
  { name: 'Noah Bennett', email: 'noah@harbor.test', admin: false, status: 'Active', mfa: 'Not enrolled', lastSeen: '3 days ago', tone: 'amber' },
  { name: 'Mina Park', email: 'mina@harbor.test', admin: false, status: 'Active', mfa: 'Authenticator app', lastSeen: 'Today, 07:15', tone: 'rose' },
  { name: 'Sam Rivera', email: 'sam@harbor.test', admin: true, status: 'Active', mfa: 'Passkey', lastSeen: 'Yesterday', tone: 'slate' },
  { name: 'Elena Costa', email: 'elena@harbor.test', admin: false, status: 'Invited', mfa: 'Not enrolled', lastSeen: 'Never', tone: 'green' },
  { name: 'Omar Haddad', email: 'omar@harbor.test', admin: false, status: 'Active', mfa: 'Not enrolled', lastSeen: 'Last week', tone: 'blue' },
];
const applications = [
  { name: 'Outline', detail: 'Team knowledge base', tone: 'green', host: 'outline.harbor.test', method: 'OIDC' },
  { name: 'Grafana', detail: 'Metrics and dashboards', tone: 'amber', host: 'metrics.harbor.test', method: 'OIDC' },
  { name: 'Forgejo', detail: 'Code and reviews', tone: 'slate', host: 'code.harbor.test', method: 'OIDC' },
  { name: 'Paperless', detail: 'Documents and records', tone: 'violet', host: 'docs.harbor.test', method: 'Forward auth' },
  { name: 'Immich', detail: 'Shared photo library', tone: 'rose', host: 'photos.harbor.test', method: 'OIDC' },
  { name: 'Home Assistant', detail: 'Home automation', tone: 'blue', host: 'home.harbor.test', method: 'Forward auth' },
];

const state = { user: null, page: 'home', appSearch: '', userSearch: '', filter: 'all', addedUsers: [], toastTimer: null };
const $ = (selector) => document.querySelector(selector);
const loginScreen = $('#loginScreen');
const appShell = $('#appShell');
const loginForm = $('#loginForm');
const emailInput = $('#email');
const passwordInput = $('#password');
const loginError = $('#loginError');
const pageContent = $('#pageContent');
const modalBackdrop = $('#modalBackdrop');
const modalContent = $('#modalContent');
const toast = $('#toast');
const sidebar = $('#sidebar');
const navScrim = $('#navScrim');
const adminPages = new Set(['applications', 'users']);

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
const allUsers = () => [...users, ...state.addedUsers];
const initials = (name) => name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase();
const avatar = (user) => `<span class="avatar tone-${user.tone}">${esc(initials(user.name))}</span>`;
const appLogo = (app, small = false) => `<span class="app-logo tone-${app.tone}${small ? ' app-logo-sm' : ''}" aria-hidden="true">${esc(app.name[0])}</span>`;
const pill = (text, kind) => `<span class="pill pill-${kind}">${esc(text)}</span>`;
const slugify = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'app';

function randomToken(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { toast.hidden = true; }, 3200);
}

function heading(title, detail, actions = '') {
  return `<div class="page-heading"><div><h1>${title}</h1><p>${detail}</p></div>${actions ? `<div class="heading-actions">${actions}</div>` : ''}</div>`;
}

function homePage() {
  const query = state.appSearch.trim().toLowerCase();
  const apps = applications.filter((app) => `${app.name} ${app.detail} ${app.host}`.toLowerCase().includes(query));
  const tiles = apps.map((app) => `<button class="app-tile" type="button" data-launch="${esc(app.name)}">${appLogo(app)}<span class="app-name">${esc(app.name)}</span><span class="app-host">${esc(app.host)}</span></button>`).join('');
  const firstName = esc(state.user.name.split(' ')[0]);
  const body = apps.length
    ? `<div class="app-grid">${tiles}</div>`
    : `<div class="panel empty"><strong>No apps match "${esc(state.appSearch)}"</strong>Try another name, or ask an admin to connect it.</div>`;
  return `${heading('My apps', `Welcome back, ${firstName}. You're signed in once; every app below opens without another password.`)}
    <section class="section"><div class="section-head"><h2>${query ? 'Search results' : 'All apps'}</h2><span>${apps.length} of ${applications.length}</span></div>${body}</section>`;
}

function applicationsPage() {
  const rows = applications.map((app) => `<tr>
    <td><div class="cell-main">${appLogo(app, true)}<span><strong>${esc(app.name)}</strong><small>${esc(app.detail)}</small></span></div></td>
    <td><span class="tag${app.method === 'OIDC' ? ' tag-accent' : ''}">${esc(app.method)}</span></td>
    <td><span class="mono">${esc(app.host)}</span></td>
    <td>${pill('Connected', 'ok')}</td>
    <td><button class="button button-secondary button-small" type="button" data-settings="${esc(app.name)}">Settings</button></td>
  </tr>`).join('');
  return `${heading('Applications', 'Apps that send people to Keystone to sign in.', '<button class="button button-primary" type="button" data-connect>Connect app</button>')}
    <ol class="how-it-works">
      <li><b>1</b><strong>Name the app</strong><span>Its name and the address people open.</span></li>
      <li><b>2</b><strong>Pick how it signs in</strong><span>OIDC if the app has an SSO setting. Forward auth if it doesn't.</span></li>
      <li><b>3</b><strong>Paste the settings</strong><span>Copy the values Keystone gives you into the app or your proxy.</span></li>
    </ol>
    <section class="panel"><div class="table-wrap"><table class="table">
      <thead><tr><th>Application</th><th>Sign-in method</th><th>Address</th><th>Status</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div></section>`;
}

function usersPage() {
  const people = allUsers();
  const query = state.userSearch.trim().toLowerCase();
  const filters = {
    all: () => true,
    admins: (user) => user.admin,
    nomfa: (user) => user.mfa === 'Not enrolled',
    invited: (user) => user.status === 'Invited',
  };
  const labels = { all: 'Everyone', admins: 'Admins', nomfa: 'No second factor', invited: 'Invited' };
  const chips = Object.keys(filters).map((key) => `<button class="chip${state.filter === key ? ' is-active' : ''}" type="button" data-filter="${key}">${labels[key]}<span>${people.filter(filters[key]).length}</span></button>`).join('');
  const shown = people.filter((user) => filters[state.filter](user) && `${user.name} ${user.email}`.toLowerCase().includes(query));
  const rows = shown.map((user) => `<tr>
    <td><div class="cell-main">${avatar(user)}<span><strong>${esc(user.name)}</strong><small>${esc(user.email)}</small></span></div></td>
    <td>${user.admin ? '<span class="tag tag-accent">Admin</span>' : '<span class="tag">Member</span>'}</td>
    <td>${user.mfa === 'Not enrolled' ? pill('Not enrolled', 'warn') : esc(user.mfa)}</td>
    <td>${user.status === 'Active' ? pill('Active', 'ok') : pill(user.status, 'neutral')}</td>
    <td>${esc(user.lastSeen)}</td>
  </tr>`).join('') || '<tr><td colspan="5"><div class="empty">No people match this filter.</div></td></tr>';
  return `${heading('People', 'Everyone who can sign in to Harbor House apps.', '<button class="button button-primary" type="button" data-invite>Invite person</button>')}
    <section class="panel">
      <div class="toolbar">${chips}<label class="search-field" for="userSearch"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input id="userSearch" type="search" placeholder="Search people" aria-label="Search people" value="${esc(state.userSearch)}"></label></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>Person</th><th>Role</th><th>Second factor</th><th>Status</th><th>Last sign-in</th></tr></thead><tbody>${rows}</tbody></table></div>
    </section>`;
}

const pages = { home: homePage, applications: applicationsPage, users: usersPage };

function renderPage() {
  if (!pages[state.page] || (adminPages.has(state.page) && !state.user.admin)) state.page = 'home';
  pageContent.innerHTML = `<div class="page">${pages[state.page]()}</div>`;
  document.querySelectorAll('.nav-link').forEach((link) => link.classList.toggle('is-active', link.dataset.page === state.page));
  $('#appCount').textContent = applications.length;
  $('#peopleCount').textContent = allUsers().length;
  closeNav();
}

function goTo(page) {
  state.page = page;
  renderPage();
  window.scrollTo(0, 0);
}

function signIn(user) {
  state.user = user;
  state.page = 'home';
  state.appSearch = '';
  $('#appSearch').value = '';
  loginScreen.hidden = true;
  appShell.hidden = false;
  $('#adminNav').hidden = !user.admin;
  $('#profileAvatar').className = `avatar tone-${user.tone}`;
  $('#profileAvatar').textContent = initials(user.name);
  $('#profileName').textContent = user.name;
  $('#profileRole').textContent = user.admin ? 'Administrator' : 'Member';
  renderPage();
}

function signOut() {
  state.user = null;
  closeModal();
  appShell.hidden = true;
  loginScreen.hidden = false;
  loginForm.reset();
  loginError.hidden = true;
  emailInput.focus();
}

function openNav() { sidebar.classList.add('is-open'); navScrim.hidden = false; $('#mobileMenu').setAttribute('aria-expanded', 'true'); }
function closeNav() { sidebar.classList.remove('is-open'); navScrim.hidden = true; $('#mobileMenu').setAttribute('aria-expanded', 'false'); }

function openModal(html) {
  modalContent.innerHTML = html;
  modalBackdrop.hidden = false;
  modalContent.querySelector('input:not([type="radio"])')?.focus();
}
function closeModal() {
  modalBackdrop.hidden = true;
  modalContent.innerHTML = '';
}

function copyRow(label, value, secret = false) {
  return `<div class="setting"><dt>${label}</dt><dd><code${secret ? ' data-secret' : ''}>${esc(value)}</code><button class="copy-button" type="button" data-copy="${esc(value)}">Copy</button></dd></div>`;
}

function connectStepOne() {
  openModal(`<p class="steps"><span class="is-current">1 · App</span><span>›</span><span>2 · Settings</span></p>
    <h2 id="modalTitle">Connect an app</h2>
    <p class="modal-intro">Keystone becomes the place this app sends people to sign in.</p>
    <form id="connectForm">
      <div class="field"><label for="appName">App name</label><input id="appName" name="name" type="text" placeholder="Grafana" required></div>
      <div class="field"><label for="appUrl">App address</label><input id="appUrl" name="url" type="url" placeholder="https://grafana.harbor.test" required></div>
      <fieldset class="field method-options">
        <legend class="field-label">How does it sign in?</legend>
        <label class="method-option" for="methodOidc"><input id="methodOidc" type="radio" name="method" value="OIDC" checked><strong>OpenID Connect</strong><small>The app has an "SSO", "OAuth" or "OpenID" setting.</small></label>
        <label class="method-option" for="methodProxy"><input id="methodProxy" type="radio" name="method" value="Forward auth"><strong>Forward auth</strong><small>The app has no SSO setting. Your reverse proxy asks Keystone first.</small></label>
      </fieldset>
      <div class="field" id="redirectField"><label for="appRedirect">Redirect URI</label><input id="appRedirect" name="redirect" type="url" placeholder="https://grafana.harbor.test/login/generic_oauth"><p class="field-hint">The callback address from the app's SSO docs. It must match exactly.</p></div>
      <div class="modal-actions"><button class="button button-secondary" type="button" data-close-modal>Cancel</button><button class="button button-primary" type="submit">Continue</button></div>
    </form>`);
}

function connectStepTwo({ name, url, method, redirect }) {
  const host = new URL(url).host;
  const slug = slugify(name);
  const app = { name, detail: method === 'OIDC' ? 'Connected with OIDC' : 'Protected by forward auth', tone: tones[applications.length % tones.length], host, method };
  applications.push(app);
  renderPage();
  let body;
  if (method === 'OIDC') {
    body = `<p class="modal-intro">Paste these into ${esc(name)}'s OpenID Connect settings.</p>
      <dl class="settings-list">
        ${copyRow('Issuer URL', issuer)}
        ${copyRow('Discovery URL', `${issuer}/.well-known/openid-configuration`)}
        ${copyRow('Client ID', `${slug}-${randomToken(6).toLowerCase()}`)}
        ${copyRow('Client secret', randomToken(40), true)}
        ${copyRow('Redirect URI (registered)', redirect)}
        ${copyRow('Scopes', 'openid profile email groups')}
      </dl>
      <p class="callout">The client secret is shown once. Store it in ${esc(name)} now.</p>`;
  } else {
    const snippet = `${host} {\n  forward_auth keystone:9000 {\n    uri /outpost/auth\n    copy_headers X-Authi-User X-Authi-Email X-Authi-Name X-Authi-Groups\n  }\n  reverse_proxy ${slug}:80\n}`;
    body = `<p class="modal-intro">Add this to your Caddyfile. Caddy asks Keystone before every request to ${esc(host)}.</p>
      <div class="setting"><div class="snippet-head"><span class="field-label">Caddyfile</span><button class="copy-button" type="button" data-copy="${esc(snippet)}">Copy</button></div><pre class="snippet">${esc(snippet)}</pre></div>
      <p class="field-hint">Using Traefik or nginx? Point their auth check at <code>${esc(baseUrl)}/outpost/auth</code>.</p>`;
  }
  openModal(`<p class="steps"><span>1 · App</span><span>›</span><span class="is-current">2 · Settings</span></p>
    <h2 id="modalTitle">${esc(name)} is connected</h2>${body}
    <div class="modal-actions"><button class="button button-primary" type="button" data-close-modal>Done</button></div>`);
  showToast(`${name} connected. It now appears in everyone's apps.`);
}

function settingsModal(name) {
  const app = applications.find((a) => a.name === name);
  if (!app) return;
  const rows = app.method === 'OIDC'
    ? `${copyRow('Issuer URL', issuer)}${copyRow('Client ID', `${slugify(app.name)}-k3s7qx`)}<div class="setting"><dt>Client secret</dt><dd><code>••••••••••••••••</code><button class="copy-button" type="button" data-rotate="${esc(app.name)}">Rotate</button></dd></div>`
    : `${copyRow('Auth endpoint', `${baseUrl}/outpost/auth`)}${copyRow('Protected address', app.host)}`;
  openModal(`<h2 id="modalTitle">${esc(app.name)}</h2><p class="modal-intro">${esc(app.method)} · ${esc(app.host)}</p><dl class="settings-list">${rows}</dl>
    <div class="modal-actions"><button class="button button-primary" type="button" data-close-modal>Close</button></div>`);
}

function inviteModal() {
  openModal(`<h2 id="modalTitle">Invite a person</h2><p class="modal-intro">They get access to every connected app after their first sign-in.</p>
    <form id="inviteForm">
      <div class="field"><label for="inviteName">Full name</label><input id="inviteName" name="name" type="text" placeholder="Taylor Reed" required></div>
      <div class="field"><label for="inviteEmail">Email</label><input id="inviteEmail" name="email" type="email" placeholder="taylor@harbor.test" required></div>
      <div class="modal-actions"><button class="button button-secondary" type="button" data-close-modal>Cancel</button><button class="button button-primary" type="submit">Send invite</button></div>
    </form>`);
}

async function copyText(button) {
  const value = button.dataset.copy;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = 'Copied';
  } catch {
    const target = button.closest('.setting')?.querySelector('code, .snippet');
    if (target) window.getSelection().selectAllChildren(target);
    button.textContent = 'Selected';
  }
  setTimeout(() => { button.textContent = 'Copy'; }, 1600);
}

loginForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const email = emailInput.value.trim().toLowerCase();
  const account = users.find((user) => user.email === email && user.status === 'Active');
  if (!account || passwordInput.value !== demoPassword) {
    loginError.textContent = 'Email or password is incorrect. Pick a sample account below, or use the password keystone-demo.';
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
  loginForm.requestSubmit();
}));

$('#togglePassword').addEventListener('click', (event) => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} password`);
});
$('#helpLink').addEventListener('click', () => showToast('An admin can send you a reset link. In this preview, pick a sample account.'));
$('#profileButton').addEventListener('click', signOut);
$('#mobileMenu').addEventListener('click', () => (sidebar.classList.contains('is-open') ? closeNav() : openNav()));
navScrim.addEventListener('click', closeNav);
$('#modalClose').addEventListener('click', closeModal);
modalBackdrop.addEventListener('click', (event) => { if (event.target === modalBackdrop) closeModal(); });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { closeModal(); closeNav(); } });

$('#appSearch').addEventListener('input', (event) => {
  state.appSearch = event.target.value;
  if (state.page !== 'home') state.page = 'home';
  renderPage();
});

document.addEventListener('click', (event) => {
  const target = event.target;
  const pageButton = target.closest('[data-page]');
  if (pageButton && state.user) { goTo(pageButton.dataset.page); return; }
  const filter = target.closest('[data-filter]');
  if (filter) { state.filter = filter.dataset.filter; renderPage(); return; }
  if (target.closest('[data-connect]')) { connectStepOne(); return; }
  if (target.closest('[data-invite]')) { inviteModal(); return; }
  if (target.closest('[data-close-modal]')) { closeModal(); return; }
  const settings = target.closest('[data-settings]');
  if (settings) { settingsModal(settings.dataset.settings); return; }
  const copy = target.closest('[data-copy]');
  if (copy) { copyText(copy); return; }
  const rotate = target.closest('[data-rotate]');
  if (rotate) { showToast(`New secret for ${rotate.dataset.rotate} would be shown once here.`); return; }
  const launch = target.closest('[data-launch]');
  if (launch) showToast(`${launch.dataset.launch} would open signed in. Sample link, nothing was opened.`);
});

document.addEventListener('change', (event) => {
  if (event.target.name === 'method') {
    const oidc = event.target.value === 'OIDC';
    $('#redirectField').hidden = !oidc;
    $('#appRedirect').required = oidc;
  }
});

document.addEventListener('submit', (event) => {
  const form = event.target;
  if (form.id === 'connectForm') {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    const name = String(data.name ?? '').trim();
    if (applications.some((app) => app.name.toLowerCase() === name.toLowerCase())) {
      showToast(`${name} is already connected.`);
      return;
    }
    connectStepTwo({ name, url: data.url, method: data.method, redirect: data.redirect });
  }
  if (form.id === 'inviteForm') {
    event.preventDefault();
    const data = new FormData(form);
    const name = String(data.get('name')).trim();
    const email = String(data.get('email')).trim().toLowerCase();
    if (allUsers().some((user) => user.email === email)) { showToast('That email already has access.'); return; }
    state.addedUsers.push({ name, email, admin: false, status: 'Invited', mfa: 'Not enrolled', lastSeen: 'Never', tone: tones[allUsers().length % tones.length] });
    closeModal();
    renderPage();
    showToast(`Invite ready for ${name}. Nothing is sent in this preview.`);
  }
});

document.addEventListener('input', (event) => {
  if (event.target.id !== 'userSearch') return;
  const cursor = event.target.selectionStart;
  state.userSearch = event.target.value;
  renderPage();
  const next = $('#userSearch');
  next.focus();
  next.setSelectionRange(cursor, cursor);
});
