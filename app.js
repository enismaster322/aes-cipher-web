/**
 * Application Controller for AES Cipher Web (Unified Window Layout)
 */

import { encryptText, decryptText } from './crypto.js';

// DOM Elements
const passphraseInput = document.getElementById('passphrase-input');
const toggleKeyBtn = document.getElementById('toggle-key-visibility');
const generateKeyBtn = document.getElementById('generate-key-btn');
const mainInput = document.getElementById('main-input');
const mainOutput = document.getElementById('main-output');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const swapBtn = document.getElementById('swap-btn');
const copyOutputBtn = document.getElementById('copy-output-btn');
const clearInputBtn = document.getElementById('clear-input-btn');
const pasteInputBtn = document.getElementById('paste-input-btn');
const sampleKeyBtn = document.getElementById('sample-key-btn');
const toastContainer = document.getElementById('toast-container');

/**
 * Displays a non-intrusive toast notification.
 * @param {string} message - Message to display.
 * @param {'success' | 'error'} type - Notification type.
 */
function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 200);
  }, 2400);
}

/**
 * Generates a high-entropy random passphrase.
 * @returns {string} 32-character random string.
 */
function generateSecurePassphrase() {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => chars[byte % chars.length]).join('');
}

/**
 * Performs encryption of input text using current passphrase.
 */
async function handleEncrypt() {
  const passphrase = passphraseInput.value.trim();
  const input = mainInput.value.trim();

  if (!passphrase) {
    showToast('Введите секретный ключ (пароль)', 'error');
    passphraseInput.focus();
    return;
  }

  if (!input) {
    showToast('Введите текст для зашифровки', 'error');
    mainInput.focus();
    return;
  }

  try {
    const result = await encryptText(input, passphrase);
    mainOutput.value = result;
    showToast('Текст зашифрован');
  } catch (err) {
    showToast(err.message || 'Ошибка шифрования', 'error');
  }
}

/**
 * Performs decryption of input Base64 text using current passphrase.
 */
async function handleDecrypt() {
  const passphrase = passphraseInput.value.trim();
  const input = mainInput.value.trim();

  if (!passphrase) {
    showToast('Введите секретный ключ (пароль)', 'error');
    passphraseInput.focus();
    return;
  }

  if (!input) {
    showToast('Вставьте зашифрованную Base64-строку для расшифровки', 'error');
    mainInput.focus();
    return;
  }

  try {
    const result = await decryptText(input, passphrase);
    mainOutput.value = result;
    showToast('Данные успешно расшифрованы');
  } catch (err) {
    showToast(err.message || 'Ошибка расшифровки', 'error');
  }
}

/**
 * Copies specified text to clipboard with fallback.
 * @param {string} text
 * @param {string} successMessage
 */
async function copyToClipboard(text, successMessage) {
  if (!text) {
    showToast('Нет данных для копирования', 'error');
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    showToast(successMessage);
  } catch {
    const tempInput = document.createElement('textarea');
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    showToast(successMessage);
  }
}

// Event Listeners
encryptBtn.addEventListener('click', handleEncrypt);
decryptBtn.addEventListener('click', handleDecrypt);

// Toggle password visibility
toggleKeyBtn.addEventListener('click', () => {
  const isPassword = passphraseInput.type === 'password';
  passphraseInput.type = isPassword ? 'text' : 'password';
  toggleKeyBtn.style.color = isPassword ? 'var(--text-main)' : '';
});

// Generate key button
generateKeyBtn.addEventListener('click', () => {
  passphraseInput.value = generateSecurePassphrase();
  passphraseInput.type = 'text';
  showToast('Сгенерирован пароль');
});

// Sample key button
sampleKeyBtn.addEventListener('click', () => {
  mainInput.value = 'ExampleSensitiveValue_12345';
  if (!passphraseInput.value) {
    passphraseInput.value = 'sample-passphrase';
  }
  showToast('Вставлен тестовый пример');
});

// Swap result to input
swapBtn.addEventListener('click', () => {
  if (!mainOutput.value) {
    showToast('Поле результата пустое', 'error');
    return;
  }
  mainInput.value = mainOutput.value;
  mainOutput.value = '';
  showToast('Результат перемещен во входное поле');
});

// Clear input
clearInputBtn.addEventListener('click', () => {
  mainInput.value = '';
  mainOutput.value = '';
  mainInput.focus();
});

// Paste input
pasteInputBtn.addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    mainInput.value = text;
    showToast('Вставлено из буфера');
  } catch {
    showToast('Разрешите доступ к буферу обмена или вставьте вручную', 'error');
  }
});

// Copy output
copyOutputBtn.addEventListener('click', () => {
  copyToClipboard(mainOutput.value, 'Результат скопирован в буфер!');
});
