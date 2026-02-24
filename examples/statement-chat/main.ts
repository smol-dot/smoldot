import { start } from "smoldot";
import { getSmProvider } from "polkadot-api/sm-provider";
import { createClient } from "polkadot-api";
import { createSignedStatement, decodeStatement, getPublicKey } from "./statement.ts";

// UI Elements
const statusEl = document.getElementById("status") as HTMLDivElement;
const topicInput = document.getElementById("topicInput") as HTMLInputElement;
const subscribeBtn = document.getElementById("subscribeBtn") as HTMLButtonElement;
const messagesEl = document.getElementById("messages") as HTMLDivElement;
const messageInput = document.getElementById("messageInput") as HTMLInputElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;
const logEl = document.getElementById("log") as HTMLDivElement;

// State
let smoldotClient = null;
let currentTopic = null;
let isSubscribed = false;

// Logging helper
function log(message, type = "default") {
  const entry = document.createElement("div");
  entry.className = `log-entry ${type}`;
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
  console.log(message);
}

// Update status
function setStatus(message, type) {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
}

// Add message to UI
function addMessage(content, type, timestamp = new Date()) {
  const placeholder = messagesEl.querySelector(".no-messages");
  if (placeholder) placeholder.remove();

  const msg = document.createElement("div");
  msg.className = `message ${type}`;

  msg.innerHTML = `
    <div class="meta">${type === "sent" ? "You" : "Received"} - ${timestamp.toLocaleTimeString()}</div>
    <div class="content">${escapeHtml(content)}</div>
  `;
  messagesEl.appendChild(msg);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Validate topic hex
function isValidTopic(topic) {
  if (!topic.startsWith("0x")) return false;
  const hex = topic.slice(2);
  return hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex);
}

// Load config from dev.sh generated file
async function loadConfig() {
  const response = await fetch("/config.json");
  if (!response.ok) {
    throw new Error("Failed to load config.json - run dev.sh first");
  }
  return await response.json();
}

// Initialize smoldot and connect
async function initialize() {
  try {
    log("Starting smoldot for statement store...", "info");
    setStatus("Starting smoldot...", "connecting");

    const smoldot = start({
      maxLogLevel: 3,
      logCallback: (level, target, message) => {
        if (level <= 2) {
          log(`[smoldot] ${message}`, level === 1 ? "error" : "info");
        } else {
          console.log(`[smoldot] ${message}`);
        }
      }
    });

    log("Loading chain specs...", "info");

    const relayChainSpec = await loadChainSpec("/chain-specs/rococo-local.json");
    const parachainSpec = await loadChainSpec("/chain-specs/parachain.json");

    log("Adding relay chain...", "info");

    const relayChain = await smoldot.addChain({
      chainSpec: relayChainSpec,
    });

    log("Adding parachain...", "info");

    const chain = await smoldot.addChain({
      chainSpec: parachainSpec,
      potentialRelayChains: [relayChain],
    });

    log("Creating smoldot client...", "info");
    const provider = getSmProvider(chain);
    const wrappedProvider = wrapProviderForNotifications(provider);
    smoldotClient = createClient(wrappedProvider);

    const rpcMethods = await smoldotClient._request("rpc_methods", []);
    const statementMethods = rpcMethods.methods.filter(m => m.includes("statement"));
    log(`Statement methods available: ${statementMethods.join(", ") || "NONE"}`, "info");

    const chainName = await smoldotClient._request("system_chain", []);
    setStatus(`Connected to ${chainName}`, "connected");

    const pubKey = await getPublicKey();
    log(`Statement signing key: ${pubKey}`, "info");

    subscribeBtn.disabled = false;
    topicInput.value = "0x0000000000000000000000000000000000000000000000000000000000000001";

  } catch (error) {
    log(`Failed to initialize: ${error.message}`, "error");
    setStatus(`Error: ${error.message}`, "error");
    console.error(error);
  }
}

// Load chain spec from file
async function loadChainSpec(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Failed to load chain spec from ${path}: ${response.statusText}`);
  }
  return await response.text();
}

// Current subscription ID
let subscriptionId = null;

// Subscribe to a topic
async function subscribeToTopic() {
  const topic = topicInput.value.trim();

  if (!isValidTopic(topic)) {
    log("Invalid topic format. Must be 0x followed by 64 hex characters.", "error");
    return;
  }

  try {
    if (subscriptionId) {
      try {
        await smoldotClient._request("statement_unsubscribe", [subscriptionId]);
      } catch (e) {
        console.debug("Unsubscribe error:", e);
      }
    }

    log(`Subscribing to topic: ${topic}`, "info");

    subscriptionId = await smoldotClient._request("statement_subscribe", [[topic]]);
    log(`Subscription ID: ${subscriptionId}`, "info");

    currentTopic = topic;
    isSubscribed = true;

    log("Subscribed successfully!", "info");
    setStatus(`Subscribed to topic: ${topic.slice(0, 10)}...`, "connected");

    messageInput.disabled = false;
    sendBtn.disabled = false;
    subscribeBtn.textContent = "Change Topic";

  } catch (error) {
    log(`Failed to subscribe: ${error.message}`, "error");
    console.error(error);
  }
}

// Send a statement
async function sendStatement() {
  const message = messageInput.value.trim();
  if (!message || !currentTopic) return;

  try {
    const statementHex = await createSignedStatement(currentTopic, message);
    log(`Sending signed statement: ${message}`, "info");

    const result = await smoldotClient._request("statement_submit", [statementHex]);

    if (result === "ok_broadcast" || result === "ok_ignore") {
      messageInput.value = "";
      log("Statement sent successfully (waiting for confirmation)", "info");
    } else if (result?.error) {
      log(`Failed to send: ${result.error}`, "error");
    } else {
      messageInput.value = "";
      log(`Statement submit result: ${JSON.stringify(result)}`, "info");
    }

  } catch (error) {
    log(`Failed to send statement: ${error.message}`, "error");
    console.error(error);
  }
}

// Handle incoming statements
let myPublicKey = null;
let seenStatements = new Set();

async function handleStatementNotification(statementHex) {
  if (seenStatements.has(statementHex)) return;
  seenStatements.add(statementHex);

  if (!myPublicKey) {
    myPublicKey = await getPublicKey();
  }

  console.log("STATEMENT RECV");

  try {
    const decoded = decodeStatement(statementHex);
    if (decoded.data) {
      const signerHex = decoded.proof?.signer
        ? "0x" + Array.from(decoded.proof.signer).map((b: number) => b.toString(16).padStart(2, "0")).join("")
        : null;
      const isOurs = signerHex === myPublicKey;

      addMessage(decoded.data, isOurs ? "sent" : "received");
    }
  } catch (e) {
    log(`Failed to decode statement: ${e.message}`, "error");
  }
}

// Wrap provider to intercept statement notifications
function wrapProviderForNotifications(provider) {
  return (onMessage) => {
    const wrappedOnMessage = (msg) => {
      try {
        const parsed = JSON.parse(msg);
        if (parsed.method === "statement_notification" && parsed.params) {
          const { subscription, statement } = parsed.params;
          handleStatementNotification(statement);
          return;
        }
      } catch (e) {}
      onMessage(msg);
    };
    return provider(wrappedOnMessage);
  };
}

// Event listeners
subscribeBtn.addEventListener("click", subscribeToTopic);
sendBtn.addEventListener("click", sendStatement);
messageInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !sendBtn.disabled) {
    sendStatement();
  }
});
topicInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !subscribeBtn.disabled) {
    subscribeToTopic();
  }
});

// Start
initialize();
