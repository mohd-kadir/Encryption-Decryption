// Helper to convert text to ArrayBuffer and vice versa
function str2ab(str) {
  return new TextEncoder().encode(str);
}
function ab2str(buf) {
  return new TextDecoder().decode(buf);
}
function buf2base64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base642buf(base64) {
  return new Uint8Array(atob(base64).split("").map(c => c.charCodeAt(0)));
}

// Derive key from password
async function getKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    str2ab(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Encrypt
async function encryptMessage() {
  const password = document.getElementById("password").value;
  const plaintext = document.getElementById("plaintext").value;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await getKey(password, salt);
  const encoded = str2ab(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(ciphertext)]);
  document.getElementById("ciphertext").value = buf2base64(combined);
}

// Decrypt
async function decryptMessage() {
  const password = document.getElementById("password").value;
  const ciphertextBase64 = document.getElementById("ciphertext").value;

  const combined = base642buf(ciphertextBase64);
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);

  const key = await getKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    document.getElementById("decrypted").value = ab2str(decrypted);
  } catch (err) {
    alert("❌ Decryption failed! Wrong password or corrupted ciphertext.");
  }
}

// Read a file and return ArrayBuffer
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result);
    reader.onerror = err => reject(err);
    reader.readAsArrayBuffer(file);
  });
}

// Download ArrayBuffer as a file
function downloadBuffer(buf, filename) {
  const blob = new Blob([buf]);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();

  document.getElementById("fileStatus").innerText = `✅ File ready: ${filename}`;
}

async function encryptFile() {
  const file = document.getElementById("fileInput").files[0];
  const password = document.getElementById("filePassword").value;

  if (!file || !password) {
    alert("Please select a file and enter a password!");
    return;
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await getKey(password, salt);
  const fileData = await readFileAsArrayBuffer(file);

  // Convert filename to bytes
  const filenameBytes = str2ab(file.name);
  const filenameLength = filenameBytes.length;

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    fileData
  );

  // Final structure: [1-byte length][filename][salt][iv][ciphertext]
  const totalLength = 1 + filenameLength + 16 + 12 + encrypted.byteLength;
  const combined = new Uint8Array(totalLength);
  combined[0] = filenameLength;
  combined.set(filenameBytes, 1);
  combined.set(salt, 1 + filenameLength);
  combined.set(iv, 1 + filenameLength + 16);
  combined.set(new Uint8Array(encrypted), 1 + filenameLength + 16 + 12);

  downloadBuffer(combined, file.name + ".enc");
}

async function decryptFile() {
  const file = document.getElementById("fileInput").files[0];
  const password = document.getElementById("filePassword").value;

  if (!file || !password) {
    alert("Please select an encrypted file and enter password!");
    return;
  }

  const combined = new Uint8Array(await readFileAsArrayBuffer(file));

  // Extract filename
  const filenameLength = combined[0];
  const filenameBytes = combined.slice(1, 1 + filenameLength);
  const originalFilename = ab2str(filenameBytes);

  // Extract salt, IV, and ciphertext
  const saltStart = 1 + filenameLength;
  const ivStart = saltStart + 16;
  const cipherStart = ivStart + 12;

  const salt = combined.slice(saltStart, ivStart);
  const iv = combined.slice(ivStart, cipherStart);
  const encryptedData = combined.slice(cipherStart);

  const key = await getKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encryptedData
    );
    downloadBuffer(decrypted, originalFilename);
  } catch (err) {
    alert("❌ Decryption failed. Check your password or file!");
  }
}

function toggleFilePassword() {
  const pwdInput = document.getElementById("filePassword");
  pwdInput.type = pwdInput.type === "password" ? "text" : "password";
}

const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");

// Click handler to trigger file picker
dropZone.addEventListener("click", (e) => {
  if (e.target.id === "fileInput") return; // prevent recursive firing
  fileInput.click();
});

// Drag events
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length > 0) {
    fileInput.files = e.dataTransfer.files;
    document.getElementById("fileStatus").innerText = `📄 File selected: ${fileInput.files[0].name}`;
  }
});

// Also update file name on manual file selection
fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) {
    document.getElementById("fileStatus").innerText = `📄 File selected: ${fileInput.files[0].name}`;
  }
});