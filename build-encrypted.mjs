// Build the password-protected gallery.
//
// Reads gallery.html (the real page) + the assets it references under src/,
// inlines every asset as a data: URI, encrypts the result with AES-256-GCM
// (key derived from the password via PBKDF2, 600k iterations), and writes:
//   payload.enc  – salt + iv + ciphertext, base64
//   index.html   – the password gate that fetches and decrypts payload.enc
//
// Usage:  GALLERY_PASSWORD='...' node build-encrypted.mjs
// The password is never written to disk.

import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';

const password = process.env.GALLERY_PASSWORD;
if (!password) { console.error('Set GALLERY_PASSWORD'); process.exit(1); }

// --- Inline assets (each embedded exactly once, in a runtime map) ------
let html = readFileSync('gallery.html', 'utf8');
const assets = {};
for (const f of readdirSync('src')) {
  if (f.startsWith('.')) continue;
  const mime = f.endsWith('.png') ? 'image/png' : 'image/gif';
  assets[`src/${f}`] = `data:${mime};base64,${readFileSync(`src/${f}`).toString('base64')}`;
}
html = html.replace('const ASSETS = {};', `const ASSETS = ${JSON.stringify(assets)};`);
if (!html.includes('data:image')) { console.error('asset injection failed'); process.exit(1); }

// --- Encrypt ----------------------------------------------------------
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
  keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(html)));

const payload = Buffer.concat([salt, iv, cipher]);
writeFileSync('payload.enc', payload);
console.log(`payload.enc written (${(payload.length / 1024 / 1024).toFixed(1)} MB)`);
