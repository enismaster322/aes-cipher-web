/**
 * AES-256-CBC Crypto Module (Web Crypto API)
 * Standard OpenSSL-compatible AES-CBC implementation.
 */

const IV_LENGTH_BYTES = 16;
const ALGORITHM_NAME = 'AES-CBC';

/**
 * Converts a Uint8Array into a Base64 string.
 * @param {Uint8Array} bytes - Binary data to encode.
 * @returns {string} Base64 encoded string.
 */
export function uint8ArrayToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string into a Uint8Array.
 * Removes extra whitespace and line breaks before decoding.
 * @param {string} base64 - Base64 encoded string.
 * @returns {Uint8Array} Decoded byte array.
 */
export function base64ToUint8Array(base64) {
  const clean = base64.trim().replace(/\s+/g, '');
  if (!clean) {
    throw new Error('Input payload is empty');
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derives a 256-bit AES key from a passphrase using SHA-256.
 * Standard raw SHA-256 digest of UTF-8 passphrase bytes.
 * @param {string} passphrase - User provided secret key.
 * @returns {Promise<CryptoKey>} Imported CryptoKey object.
 */
export async function deriveKey(passphrase) {
  if (!passphrase) {
    throw new Error('Secret key (passphrase) cannot be empty');
  }
  const encoder = new TextEncoder();
  const keyBytes = encoder.encode(passphrase);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);

  return crypto.subtle.importKey(
    'raw',
    hashBuffer,
    { name: ALGORITHM_NAME },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts plain text using AES-256-CBC.
 * Output format: Base64(IV [16 bytes] + Ciphertext).
 * @param {string} plainText - Text to encrypt.
 * @param {string} passphrase - Secret passphrase.
 * @returns {Promise<string>} Base64 encrypted payload.
 */
export async function encryptText(plainText, passphrase) {
  if (typeof plainText !== 'string') {
    throw new Error('Plaintext must be a string');
  }
  const cryptoKey = await deriveKey(passphrase);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(plainText);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: ALGORITHM_NAME, iv },
    cryptoKey,
    encodedData
  );

  const combined = new Uint8Array(iv.length + cipherBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuffer), iv.length);

  return uint8ArrayToBase64(combined);
}

/**
 * Decrypts a Base64 AES-256-CBC payload.
 * Expects the first 16 bytes to be the IV.
 * @param {string} cipherTextB64 - Base64 payload containing IV + ciphertext.
 * @param {string} passphrase - Secret passphrase.
 * @returns {Promise<string>} Decrypted plain text.
 */
export async function decryptText(cipherTextB64, passphrase) {
  const cryptoKey = await deriveKey(passphrase);
  const rawBytes = base64ToUint8Array(cipherTextB64);

  if (rawBytes.length <= IV_LENGTH_BYTES) {
    throw new Error('Payload too short: missing ciphertext data');
  }

  const iv = rawBytes.slice(0, IV_LENGTH_BYTES);
  const cipherBytes = rawBytes.slice(IV_LENGTH_BYTES);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: ALGORITHM_NAME, iv },
      cryptoKey,
      cipherBytes
    );
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return decoder.decode(decryptedBuffer);
  } catch (err) {
    throw new Error('Decryption failed: invalid key or corrupted payload');
  }
}
