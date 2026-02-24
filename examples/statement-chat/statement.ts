import * as ed from "@noble/ed25519";

// SCALE compact integer encoding
function encodeCompact(value) {
  if (value < 0x40) {
    return new Uint8Array([value << 2]);
  } else if (value < 0x4000) {
    const v = (value << 2) | 0x01;
    return new Uint8Array([v & 0xff, v >> 8]);
  } else if (value < 0x40000000) {
    const v = (value << 2) | 0x02;
    return new Uint8Array([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, v >> 24]);
  } else {
    throw new Error("Value too large for compact encoding");
  }
}

// Concatenate multiple Uint8Arrays
function concat(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Convert hex string to 32-byte topic
function hexToTopic(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex.length !== 64) throw new Error("Topic must be 32 bytes (64 hex chars)");
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

// Encode proof (Ed25519 variant = 1)
function encodeEd25519Proof(signature, publicKey) {
  return concat(
    new Uint8Array([1]), // Ed25519 variant discriminant
    signature,           // 64 bytes
    publicKey            // 32 bytes
  );
}

// Build signature material (statement fields without proof, without length prefix)
function buildSignatureMaterial(topic, data) {
  const parts = [];

  // Field 4: Topic (discriminant + 32 bytes)
  parts.push(new Uint8Array([4]));
  parts.push(hexToTopic(topic));

  // Field 8: Data (discriminant + SCALE-encoded Vec<u8>)
  const dataBytes = new TextEncoder().encode(data);
  parts.push(new Uint8Array([8]));
  parts.push(encodeCompact(dataBytes.length));
  parts.push(dataBytes);

  return concat(...parts);
}

// Encode full statement with proof
function encodeStatement(proof, topic, data) {
  const parts = [];

  // Number of fields: 3 (proof + topic + data)
  parts.push(encodeCompact(3));

  // Field 0: Proof
  parts.push(new Uint8Array([0]));
  parts.push(proof);

  // Field 4: Topic
  parts.push(new Uint8Array([4]));
  parts.push(hexToTopic(topic));

  // Field 8: Data
  const dataBytes = new TextEncoder().encode(data);
  parts.push(new Uint8Array([8]));
  parts.push(encodeCompact(dataBytes.length));
  parts.push(dataBytes);

  return concat(...parts);
}

// Generate or retrieve Ed25519 keypair from localStorage
async function getOrCreateKeypair() {
  const stored = localStorage.getItem("statement-chat-keypair");
  if (stored) {
    const { privateKey, publicKey } = JSON.parse(stored);
    return {
      privateKey: new Uint8Array(privateKey),
      publicKey: new Uint8Array(publicKey),
    };
  }

  // Generate new keypair
  const privateKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  localStorage.setItem("statement-chat-keypair", JSON.stringify({
    privateKey: Array.from(privateKey),
    publicKey: Array.from(publicKey),
  }));

  return { privateKey, publicKey };
}

// Create and sign a statement
export async function createSignedStatement(topic, data) {
  const { privateKey, publicKey } = await getOrCreateKeypair();

  // Build signature material (statement without proof, without length prefix)
  const signatureMaterial = buildSignatureMaterial(topic, data);

  // Sign the material
  const signature = await ed.signAsync(signatureMaterial, privateKey);

  // Encode the proof
  const proof = encodeEd25519Proof(signature, publicKey);

  // Encode the full statement
  const statement = encodeStatement(proof, topic, data);

  return "0x" + Array.from(statement).map((b: number) => b.toString(16).padStart(2, "0")).join("");
}

// Get current public key (for display)
export async function getPublicKey() {
  const { publicKey } = await getOrCreateKeypair();
  return "0x" + Array.from(publicKey).map((b: number) => b.toString(16).padStart(2, "0")).join("");
}

// Decode a received statement
export function decodeStatement(hexData) {
  if (hexData.startsWith("0x")) hexData = hexData.slice(2);
  const bytes = new Uint8Array(hexData.match(/.{2}/g).map(b => parseInt(b, 16)));

  let offset = 0;

  // Read compact-encoded number of fields
  const [numFields, fieldCountSize] = readCompact(bytes, offset);
  offset += fieldCountSize;

  let proof = null;
  let topic = null;
  let data = null;

  for (let i = 0; i < numFields; i++) {
    const discriminant = bytes[offset++];

    switch (discriminant) {
      case 0: // Proof
        const proofType = bytes[offset++];
        if (proofType === 1) { // Ed25519
          const signature = bytes.slice(offset, offset + 64);
          offset += 64;
          const signer = bytes.slice(offset, offset + 32);
          offset += 32;
          proof = { type: "Ed25519", signature, signer };
        } else {
          throw new Error(`Unsupported proof type: ${proofType}`);
        }
        break;
      case 4: case 5: case 6: case 7: // Topics
        topic = bytes.slice(offset, offset + 32);
        offset += 32;
        break;
      case 8: // Data
        const [dataLen, dataLenSize] = readCompact(bytes, offset);
        offset += dataLenSize;
        data = bytes.slice(offset, offset + dataLen);
        offset += dataLen;
        break;
      default:
        throw new Error(`Unknown field discriminant: ${discriminant}`);
    }
  }

  return {
    proof,
    topic: topic ? "0x" + Array.from(topic).map((b: number) => b.toString(16).padStart(2, "0")).join("") : null,
    data: data ? new TextDecoder().decode(data) : null,
  };
}

// Helper to read SCALE compact integer
function readCompact(bytes, offset) {
  const mode = bytes[offset] & 0x03;
  if (mode === 0) {
    return [bytes[offset] >> 2, 1];
  } else if (mode === 1) {
    const value = (bytes[offset] | (bytes[offset + 1] << 8)) >> 2;
    return [value, 2];
  } else if (mode === 2) {
    const value = (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >> 2;
    return [value, 4];
  } else {
    throw new Error("Big integer compact encoding not supported");
  }
}
