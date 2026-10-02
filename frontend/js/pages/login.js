import { login } from '../api.js';
import { h, icon } from '../dom.js';

export function renderLogin(onSuccess) {
  const error = h('p', { class: 'form-error', role: 'alert' });
  const username = h('input', { id: 'username', name: 'username', autocomplete: 'username', required: true, maxlength: 64 });
  const password = h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'current-password',
    required: true, maxlength: 256 });
  const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Sign in');

  const form = h('form', { class: 'login-form', novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    error.textContent = '';
    if (!username.value || !password.value) { error.textContent = 'Enter your username and password.'; return; }
    submit.disabled = true;
    submit.textContent = 'Signing in…';
    try {
      await login(username.value.trim(), password.value);
      onSuccess();
    } catch (err) {
      error.textContent = err.message;
      submit.disabled = false;
      submit.textContent = 'Sign in';
      password.value = '';
      password.focus();
    }
  } },
  h('label', { for: 'username' }, 'Username'), username,
  h('label', { for: 'password' }, 'Password'), password,
  error, submit);

  setTimeout(() => username.focus(), 0);
  return h('div', { class: 'login-page' },
    h('div', { class: 'login-card' },
      h('div', { class: 'login-brand' }, icon('shield', 'icon brand-icon lg'), h('span', {}, 'MerkleTrust')),
      h('h1', {}, 'Check whether an Android app can be trusted'),
      h('p', { class: 'muted' }, 'Verify that an app is the same as its trusted version, see exactly what changed, ' +
        'and get cryptographic proof of every result.'),
      form),
    h('p', { class: 'muted small center' }, 'Academic prototype — Cryptography and Network Security project.'));
}
