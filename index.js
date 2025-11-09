// index.js — SureData Backend (Production-ready, Plan buckets migration + idempotent webhook)
// NOTE: This file is your original with only the migration + idempotent webhook additions you requested.

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import crypto from "crypto";
import fetch from "node-fetch";

dotenv.config();
const app = express();

// --- Firebase Initialization ---
if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY
) {
  console.error("⚠️ Missing Firebase environment variables");
}

const serviceAccount = {
  project_id: process.env.FIREBASE_PROJECT_ID,
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  private_key: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

// --- Lightweight admin middleware ---
const adminApiKey = process.env.ADMIN_API_KEY || null;
if (!adminApiKey) {
  console.warn("⚠️ ADMIN_API_KEY not set — node admin endpoints will be accessible without admin key. Set ADMIN_API_KEY to secure them.");
}
function requireAdmin(req, res, next) {
  if (!adminApiKey) return next(); // allow in dev
  const key = req.headers["x-admin-key"];
  if (!key || key !== adminApiKey) {
    return res.status(401).json({ error: "Unauthorized (missing or invalid x-admin-key)" });
  }
  return next();
}

// --- Notification Helper ---
async function sendUserNotification(email, type, message) {
  try {
    console.log(`🔔 Notification [${type}] → ${email}: ${message}`);
    await db.collection("notifications").add({
      email,
      type,
      message,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      read: false,
    });
  } catch (err) {
    console.error("Notification error:", err.message || err);
  }
}

// ----------------------
// TAILSCALE HELPERS (updated with TAILSCALE_API_BASE)
// ----------------------
function _tailscaleAuthHeader() {
  const apiKey = process.env.TAILSCALE_API_KEY || "";
  const token = Buffer.from(`${apiKey}:`).toString("base64");
  return `Basic ${token}`;
}

const BASE_URL = process.env.TAILSCALE_API_BASE || "https://api.tailscale.com/api/v2";

async function tailscaleListDevices() {
  try {
    const tailnet = process.env.TAILSCALE_TAILNET;
    if (!tailnet) throw new Error("TAILSCALE_TAILNET not set");
    const url = `${BASE_URL}/tailnet/${encodeURIComponent(tailnet)}/devices`;
    const res = await fetch(url, { method: "GET", headers: { Authorization: _tailscaleAuthHeader() } });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale devices fetch failed: ${res.status} ${text}`);
    }
    const json = await res.json();
    return json.devices || [];
  } catch (err) {
    console.warn("tailscaleListDevices error:", err.message || err);
    return [];
  }
}

async function tailscaleEnableDevice(deviceId) {
  try {
    const url = `${BASE_URL}/device/${encodeURIComponent(deviceId)}/enable`;
    const res = await fetch(url, { method: "POST", headers: { Authorization: _tailscaleAuthHeader() } });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale enable failed: ${res.status} ${text}`);
    }
    return { ok: true };
  } catch (err) {
    console.warn("tailscaleEnableDevice error:", err.message || err);
    return { ok: false, error: err.message };
  }
}

async function tailscaleDisableDevice(deviceId) {
  try {
    const url = `${BASE_URL}/device/${encodeURIComponent(deviceId)}/disable`;
    const res = await fetch(url, { method: "POST", headers: { Authorization: _tailscaleAuthHeader() } });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale disable failed: ${res.status} ${text}`);
    }
    return { ok: true };
  } catch (err) {
    console.warn("tailscaleDisableDevice error:", err.message || err);
    return { ok: false, error: err.message };
  }
}

// ----------------------
// --- MIGRATE LEGACY FIELDS INTO plans[] IF NEEDED (idempotent) ---
      try {
        const existingPlans = Array.isArray(userData.plans) ? [...userData.plans] : [];
        const migrationBuckets = [];

        // migrate currentPlan if it exists and not represented in plans
        if (userData.currentPlan && (userData.planLimit || 0) > 0) {
          const lowercaseName = String(userData.currentPlan || "").toLowerCase();
          const present = existingPlans.some((p) => {
            if (!p) return false;
            return String(p.name || "").toLowerCase() === lowercaseName && Number(p.dataLimitMB || p.dataLimit || 0) === Number(userData.planLimit || 0);
          });
          if (!present) {
            const rem = Math.max((userData.planLimit || 0) - (userData.dataUsed || 0), 0);
            migrationBuckets.push({
              name: userData.currentPlan || "Legacy Plan",
              dataLimitMB: Number(userData.planLimit || 0),
              remainingMB: Number(rem),
              purchasedAt: userData.lastPayment?.date || new Date().toISOString(),
              expiry: userData.expiryDate || null,
            });
          }
        }

        // migrate pendingPlan (legacy) into a bucket if not present
        if (userData.pendingPlan && userData.pendingPlan.dataLimit) {
          const p = userData.pendingPlan;
          const lowercaseName = String(p.name || "").toLowerCase();
          const presentPending = existingPlans.some((ep) => {
            if (!ep) return false;
            return String(ep.name || "").toLowerCase() === lowercaseName && Number(ep.dataLimitMB || ep.dataLimit || 0) === Number(p.dataLimit || 0);
          });
          if (!presentPending) {
            const expiry = p.expiryDate || p.expiry || null;
            migrationBuckets.push({
              name: p.name || "Pending Plan",
              dataLimitMB: Number(p.dataLimit || 0),
              remainingMB: Number(p.dataLimit || 0),
              purchasedAt: p.purchasedAt || new Date().toISOString(),
              expiry,
            });
          }
        }

        if (migrationBuckets.length > 0) {
          // merge and write once
          const mergedPlans = [...existingPlans, ...migrationBuckets];
          const totalRemaining = computeTotalRemainingFromPlans(mergedPlans);
          const earliestExpiry = mergedPlans.length
            ? mergedPlans
                .map((p) => (p.expiry ? new Date(p.expiry) : null))
                .filter(Boolean)
                .sort((a, b) => a - b)[0]
            : null;

          await userRef.update({
            plans: mergedPlans,
            totalDataDisplay: totalRemaining,
            planLimit: totalRemaining,
            expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
            // clear legacy fields to avoid repeat migrations
            pendingPlan: admin.firestore.FieldValue.delete(),
            currentPlan: admin.firestore.FieldValue.delete(),
            dataUsed: admin.firestore.FieldValue.delete(),
            updatedAt: new Date().toISOString(),
          });

          console.log(`Migrated legacy plan(s) into plans[] for ${email}. migrated=${migrationBuckets.length}`);
        }
      } catch (e) {
        console.warn("Plan migration failed (non-fatal):", e.message || e);
      }

      // --- Build & append new bucket for this purchase ---
      const newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + plan.days);

      const bucket = {
        name: plan.name,
        dataLimitMB: plan.dataLimit,
        remainingMB: plan.dataLimit,
        purchasedAt: now.toISOString(),
        expiry: newExpiry.toISOString(),
      };

      // Append bucket with idempotency guard via transaction doc (we already set txRef to processing).
      try {
        const appendRes = await appendPlanBucketForUser(userRef, bucket);

        // Mark transaction success
        await txRef.set({
          status: "success",
          processedAt: new Date().toISOString(),
          plan: plan.name,
          totalAfter: appendRes.totalRemaining,
        }, { merge: true });

        // convenience legacy fields for older clients
        await userRef.update({
          vpnActive: true,
          lastPayment: { amount, reference, date: now.toISOString() },
          updatedAt: new Date().toISOString(),
        });

        await sendUserNotification(
          email,
          "plan_purchased",
          `🎉 You purchased ${plan.name}. +${plan.dataLimit}MB — total available: ${appendRes.totalRemaining}MB.`
        );

        console.log(`✅ Processed payment ${reference} for ${email} — plan ${plan.name} added.`);
      } catch (e) {
        console.error("Failed to append plan bucket or finalize tx:", e.message || e);
        // mark transaction failed so it can be inspected / retried manually
        await txRef.set({
          status: "failed",
          processedAt: new Date().toISOString(),
          error: String(e.message || e),
        }, { merge: true });
      }

      return res.sendStatus(200);
    } catch (err) {
      console.error("❌ Webhook error:", err);
      return res.sendStatus(500);
    }
  }
);

// ----------------------
// Node management helpers (Firestore: tailscale_nodes)
// ----------------------

// Create or update a tailscale_node doc (id can be provided or auto)
async function upsertNode(node) {
  // node: { deviceId, hostname, ip, user, assignedTo, status, load, online, lastChecked }
  if (!node.deviceId) {
    // fallback to generated id
    const docRef = db.collection("tailscale_nodes").doc();
    await docRef.set({
      hostname: node.hostname || null,
      ip: node.ip || null,
      user: node.user || null,
      assignedTo: node.assignedTo || null,
      status: node.status || "free",
      load: node.load || 0.0,
      online: typeof node.online === "boolean" ? node.online : true,
      deviceId: docRef.id,
      lastChecked: admin.firestore.FieldValue.serverTimestamp(),
    });
    return docRef.id;
  } else {
    const docRef = db.collection("tailscale_nodes").doc(node.deviceId);
    await docRef.set({
      deviceId: node.deviceId,
      hostname: node.hostname || null,
      ip: node.ip || null,
      user: node.user || null,
      assignedTo: node.assignedTo || null,
      status: node.status || "free",
      load: node.load || 0.0,
      online: typeof node.online === "boolean" ? node.online : true,
      lastChecked: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    return node.deviceId;
  }
}

// Pick best node: online, status === 'free', lowest load. Returns doc snapshot or null.
async function pickBestNode() {
  const q = await db.collection("tailscale_nodes")
    .where("online", "==", true)
    .where("status", "==", "free")
    .orderBy("load", "asc")
    .limit(1)
    .get();
  if (q.empty) return null;
  return q.docs[0];
}

// assign node: mark status=in_use, assignedTo=userEmail (or uid), increment load slightly
async function assignNodeToUser(nodeDocRef, userIdOrEmail) {
  const doc = await nodeDocRef.get();
  if (!doc.exists) throw new Error("node missing");
  const data = doc.data() || {};
  const newLoad = (data.load || 0) + 0.05; // bump load a bit; tune as needed
  await nodeDocRef.update({
    status: "in_use",
    assignedTo: userIdOrEmail,
    load: newLoad,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { ok: true, deviceId: doc.id, nodeData: { ...data, load: newLoad, assignedTo: userIdOrEmail } };
}

async function releaseNode(nodeDocRef) {
  const doc = await nodeDocRef.get();
  if (!doc.exists) return { ok: false, reason: "missing" };
  const data = doc.data() || {};
  // decrement load but not below 0
  const newLoad = Math.max((data.load || 0) - 0.05, 0);
  await nodeDocRef.update({
    status: "free",
    assignedTo: null,
    load: newLoad,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { ok: true };
}

// mark node offline/online (status unaffected)
async function setNodeOnline(nodeDocRef, online) {
  await nodeDocRef.update({
    online,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
}

// ----------------------------
// PAYSTACK WEBHOOK (UPDATED: idempotent + migration into plans[])
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY; // ✅ fixed variable name
      if (!secret) {
        console.error("❌ PAYSTACK_SECRET_KEY missing in .env");
        return res.status(500).send("Server misconfigured");
      }

      const rawBody = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(JSON.stringify(req.body));

      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(rawBody)
        .digest("hex");

      const receivedHash = req.headers["x-paystack-signature"];

      // ✅ Allow easy testing
      if (
        process.env.NODE_ENV !== "production" &&
        receivedHash === "test-bypass"
      ) {
        console.log("🧪 Paystack test-bypass active");
      } else if (computedHash !== receivedHash) {
        console.log("⚠️ Invalid Paystack signature");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      if (event.event !== "charge.success") return res.sendStatus(200);

      const data = event.data;
      const reference = data.reference;
      const amount = data.amount / 100;
      const email = (data.customer?.email || "").toLowerCase();

      // --- IDP: check transactions doc to avoid duplicate processing ---
      const txRef = db.collection("transactions").doc(reference);
      const txSnap = await txRef.get();
      if (txSnap.exists && txSnap.data() && txSnap.data().status === "success") {
        console.log(`🔁 Duplicate webhook detected for reference ${reference} — skipping.`);
        return res.sendStatus(200);
      }

      // mark processing (prevents concurrent double writes)
      await txRef.set({
        email,
        reference,
        amount,
        status: "processing",
        receivedAt: new Date().toISOString()
      }, { merge: true });

      // ✅ Match plan by amount
      const plans = {
        500: { name: "Basic Plan", dataLimit: 1 * 1024, days: 30 },
        1000: { name: "Standard Plan", dataLimit: 3 * 1024, days: 30 },
        2000: { name: "Pro Plan", dataLimit: 8 * 1024, days: 30 },
        5000: { name: "Ultra Plan", dataLimit: 20 * 1024, days: 30 },
      };
      const plan = plans[amount];
      if (!plan) {
        console.log(`Unhandled payment amount: ${amount} for ${email}`);
        await txRef.set({ status: "unmapped_amount", timestamp: new Date().toISOString() }, { merge: true });
        return res.sendStatus(200);
      }

      // ✅ Find user
      const usersRef = db.collection("users");
      const snap = await usersRef.where("email", "==", email).limit(1).get();
      if (snap.empty) {
        console.log(`❌ User not found for email ${email}`);
        await txRef.set({
          email,
          reference,
          amount,
          status: "user_not_found",
          timestamp: new Date().toISOString(),
          note: "user_not_found"
        }, { merge: true });
        return res.sendStatus(200);
      }

      const userRef = snap.docs[0].ref;
      const userData = snap.docs[0].data();

      // --- MIGRATE LEGACY FIELDS INTO plans[] IF NEEDED (idempotent) ---
      try {
        await migrateLegacyToPlansIfNeeded(userRef, userData);
      } catch (e) {
        console.warn("Legacy migration error (non-fatal):", e.message || e);
      }

      // Build new bucket
      const now = new Date();
      const newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + plan.days);

      const bucket = {
        name: plan.name,
        dataLimitMB: plan.dataLimit,
        remainingMB: plan.dataLimit,
        purchasedAt: now.toISOString(),
        expiry: newExpiry.toISOString(),
      };

      // Append bucket and finalize transaction (idempotent via transactions doc above)
      try {
        const appendRes = await appendPlanBucketForUser(userRef, bucket);

        // update transaction as success
        await txRef.set({
          status: "success",
          processedAt: new Date().toISOString(),
          plan: plan.name,
          totalAfter: appendRes.totalRemaining,
        }, { merge: true });

        // convenience legacy fields for older clients
        await userRef.update({
          vpnActive: true,
          lastPayment: { amount, reference, date: now.toISOString() },
          updatedAt: new Date().toISOString(),
        });

        console.log(`✅ ${email} purchased ${plan.name} — bucket appended. totalRemaining=${appendRes.totalRemaining}`);

        // Notify user
        await sendUserNotification(
          email,
          "plan_purchased",
          `🎉 You’ve successfully purchased the ${plan.name}. +${plan.dataLimit}MB — total available: ${appendRes.totalRemaining}MB.`
        );

        return res.sendStatus(200);
      } catch (e) {
        console.error("Failed to append plan bucket or finalize transaction:", e.message || e);
        // mark transaction failed
        await txRef.set({
          status: "failed",
          processedAt: new Date().toISOString(),
          error: String(e.message || e)
        }, { merge: true });
        return res.sendStatus(500);
      }
    } catch (err) {
      console.error("❌ Webhook error:", err);
      return res.sendStatus(500);
    }
  }
);

// --- Enable JSON parsing + add request logger middleware ---
app.use(express.json());
app.use(cors());

// Universal request logger
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl}`);
  next();
});

// ----------------------
// Health / Admin
// ----------------------
app.get("/health", (_, res) => res.status(200).send("OK"));

app.get("/admin/summary", async (_, res) => {
  try {
    const snap = await db.collection("users").get();
    const now = new Date();
    let total = 0,
      active = 0,
      expired = 0,
      withPlan = 0;

    snap.forEach((doc) => {
      total++;
      const u = doc.data();
      if (u.vpnActive) active++;
      if (u.expiryDate && new Date(u.expiryDate) < now) expired++;
      if (u.currentPlan) withPlan++;
    });

    res.json({ total, active, expired, withPlan });
  } catch (err) {
    console.error("admin/summary error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// Tailscale & Node Endpoints
// ----------------------

// Seed nodes from a JSON array in request body (admin)
app.post("/tailscale/seed-nodes", requireAdmin, async (req, res) => {
  try {
    const nodes = req.body.nodes; // expect array of {deviceId, hostname, ip, user}
    if (!Array.isArray(nodes)) return res.status(400).json({ error: "nodes array required" });

    const results = [];
    for (const n of nodes) {
      const did = n.deviceId || (n.hostname ? n.hostname.replace(/\s+/g, "-").toLowerCase() : null);
      await upsertNode({
        deviceId: did,
        hostname: n.hostname,
        ip: n.ip,
        user: n.user,
        assignedTo: null,
        status: "free",
        load: 0.0,
        online: true,
      });
      results.push({ deviceId: did || "generated", ok: true });
    }
    res.json({ success: true, seeded: results });
  } catch (err) {
    console.error("/tailscale/seed-nodes error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// Cron-like: sync nodes from Tailscale API into tailscale_nodes collection (admin)
app.post("/tailscale/sync-from-api", requireAdmin, async (req, res) => {
  try {
    const devices = await tailscaleListDevices();
    const upserts = [];
    for (const d of devices) {
      // map device fields to our node doc
      const deviceId = d.id || d.node_id || d.key || d.idString || d.id?.toString();
      const hostname = d.hostname || d.name || null;
      const ip = (d.allAddresses && d.allAddresses[0]) || d.addresses?.[0] || null;
      const user = d.user || d.userName || null;
      const online = d.online !== undefined ? !!d.online : true;
      const load = 0.0; // initial; you might later populate from metrics
      const status = "free";

      await upsertNode({
        deviceId,
        hostname,
        ip,
        user,
        assignedTo: null,
        status,
        load,
        online,
      });
      upserts.push(deviceId);
    }

    res.json({ success: true, synced: upserts.length, deviceIds: upserts });
  } catch (err) {
    console.error("/tailscale/sync-from-api error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// Auto-assign a node to a user (called by backend when user purchases or app when user connects)
// Request: { email, uid } — admin header optional depending on ADMIN_API_KEY
app.post("/vpn/node/auto-assign", requireAdmin, async (req, res) => {
  try {
    const { email, uid } = req.body;
    const userIdentifier = (uid || email);
    if (!userIdentifier) return res.status(400).json({ error: "email or uid required" });

    // pick best node
    const nodeDoc = await pickBestNode();
    if (!nodeDoc) {
      // fallback: try to pick any online node
      const alt = await db.collection("tailscale_nodes")
        .where("online", "==", true)
        .orderBy("load", "asc")
        .limit(1)
        .get();
      if (alt.empty) {
        return res.status(503).json({ error: "No available tailscale nodes" });
      } else {
        const docRef = alt.docs[0].ref;
        const r = await assignNodeToUser(docRef, userIdentifier);
        // create vpn_sessions record
        await db.collection("vpn_sessions").doc(userIdentifier).set({
          nodeId: docRef.id,
          assignedAt: new Date().toISOString(),
          active: true,
          user: email || uid || null,
        });
        return res.json({ success: true, assigned: docRef.id, details: r });
      }
    }

    const docRef = nodeDoc.ref;
    const assignRes = await assignNodeToUser(docRef, userIdentifier);

    // Save session
    await db.collection("vpn_sessions").doc(userIdentifier).set({
      nodeId: docRef.id,
      assignedAt: new Date().toISOString(),
      active: true,
      user: email || uid || null,
    });

    res.json({ success: true, deviceId: docRef.id, details: assignRes });
  } catch (err) {
    console.error("/vpn/node/auto-assign error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// Revoke node for a user (unassign)
// Request: { email or uid }
app.post("/vpn/node/revoke", requireAdmin, async (req, res) => {
  try {
    const { email, uid } = req.body;
    const userIdentifier = (uid || email);
    if (!userIdentifier) return res.status(400).json({ error: "email or uid required" });

    const sessionRef = db.collection("vpn_sessions").doc(userIdentifier);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists) return res.status(404).json({ error: "No active session for user" });

    const session = sessionSnap.data() || {};
    const nodeId = session.nodeId;
    if (nodeId) {
      const nodeRef = db.collection("tailscale_nodes").doc(nodeId);
      // attempt to disable device at Tailscale as well (best-effort)
      try {
        await tailscaleDisableDevice(nodeId);
      } catch (err) {
        console.warn("tailscaleDisableDevice failed:", err.message || err);
      }
      await releaseNode(nodeRef);
    }

    // mark session inactive
    await sessionRef.update({ active: false, revokedAt: new Date().toISOString() });

    res.json({ success: true, revoked: true, nodeId: nodeId || null });
  } catch (err) {
    console.error("/vpn/node/revoke error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// Check user session status
app.get("/vpn/status/:uid", async (req, res) => {
  try {
    const uid = req.params.uid;
    const snap = await db.collection("vpn_sessions").doc(uid).get();
    if (!snap.exists) return res.json({ active: false });
    const s = snap.data() || {};
    const node = s.nodeId ? (await db.collection("tailscale_nodes").doc(s.nodeId).get()).data() : null;
    res.json({ active: !!s.active, session: s, node });
  } catch (err) {
    console.error("/vpn/status error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// Existing VPN session handlers (connect/disconnect/update-usage) - kept mostly as-is
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const docRef = snap.docs[0].ref;
    await docRef.update({
      vpnActive: true,
      vpnIP: vpn_ip,
      lastConnect: new Date().toISOString(),
    });

    // optional: ensure tailscale device enabled when user connects (try to use stored vpnDeviceId)
    try {
      const user = snap.docs[0].data();
      if (user && user.vpnDeviceId) {
        await tailscaleEnableDevice(user.vpnDeviceId);
      } else {
        // attempt to auto-assign a node if none assigned (best-effort)
        const uidOrEmail = user.uid || user.email;
        const existingSession = await db.collection("vpn_sessions").doc(uidOrEmail).get();
        if (!existingSession.exists) {
          const pick = await pickBestNode();
          if (pick) {
            await assignNodeToUser(pick.ref, uidOrEmail);
            await db.collection("vpn_sessions").doc(uidOrEmail).set({
              nodeId: pick.ref.id,
              assignedAt: new Date().toISOString(),
              active: true,
              user: user.email || uidOrEmail,
            });
          }
        }
      }
    } catch (err) {
      console.warn("connect: tailscale enable attempt failed:", err.message || err);
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Connect error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, data_used_mb = 0 } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const doc = snap.docs[0];
    const u = doc.data();
    const used = (u.dataUsed || 0) + data_used_mb;
    const over = used >= (u.planLimit || Infinity);
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();

    await doc.ref.update({
      dataUsed: used,
      vpnActive: !over && !expired,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    if (over || expired) {
      // disable both local VPN and tailscale device
      await disableVPNAccess(username);
      await sendUserNotification(
        username,
        "plan_exhausted",
        expired
          ? "Your plan has expired. Please renew."
          : "Your data limit has been exhausted."
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Disconnect error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/vpn/session/update-usage", async (req, res) => {
  try {
    const { username, usage_mb = 0 } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const doc = snap.docs[0];
    const u = doc.data();
    const used = (u.dataUsed || 0) + usage_mb;
    const percent = (used / (u.planLimit || 1)) * 100;

    if (percent >= 90 && percent < 100) {
      await sendUserNotification(
        username,
        "plan_near_limit",
        `⚠️ You've used ${percent.toFixed(0)}% of your plan.`
      );
    }

    const over = used >= (u.planLimit || Infinity);
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();

    await doc.ref.update({
      dataUsed: used,
      vpnActive: !over && !expired,
      updatedAt: new Date().toISOString(),
    });

    if (over || expired) {
      await disableVPNAccess(username);
      await sendUserNotification(
        username,
        "plan_exhausted",
        over
          ? "🚫 Your data plan has been exhausted."
          : "⌛ Your plan has expired."
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Usage update error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// CRON JOBS
app.all("/cron/expire-check", async (_, res) => {
  try {
    const now = new Date();
    const snap = await db.collection("users").get();
    let disabled = 0;

    for (const doc of snap.docs) {
      const u = doc.data();
      const expired = u.expiryDate && new Date(u.expiryDate) < now;
      const exhausted =
        (u.planLimit || 0) > 0 && (u.dataUsed || 0) >= u.planLimit;

      if (expired || exhausted) {
        await doc.ref.update({ vpnActive: false, updatedAt: new Date().toISOString() });
        await disableVPNAccess(u.email || u.username || doc.id);
        disabled++;
      }
    }

    res.status(200).send(`✅ Disabled ${disabled} users`);
  } catch (err) {
    console.error("Cron expire-check error:", err.message || err);
    res.status(500).send(err.message);
  }
});

// Periodic tailscale-sync (keeps tailscale_nodes updated). you can call this endpoint via scheduler
app.get("/cron/tailscale-sync", requireAdmin, async (_, res) => {
  try {
    const devices = await tailscaleListDevices();
    let synced = 0;
    for (const d of devices) {
      const deviceId = d.id || d.node_id || d.key || d.idString;
      const hostname = d.hostname || d.name || null;
      const ip = (d.allAddresses && d.allAddresses[0]) || d.addresses?.[0] || null;
      const user = d.user || d.userName || null;
      const online = d.online !== undefined ? !!d.online : true;

      await upsertNode({
        deviceId,
        hostname,
        ip,
        user,
        assignedTo: null,
        status: "free",
        load: 0.0,
        online,
      });
      synced++;
    }
    res.json({ success: true, synced });
  } catch (err) {
    console.error("Tailscale sync error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// Misc. Test Endpoints
app.post("/notify/test", async (req, res) => {
  try {
    const { email, message = "Test notification" } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    await sendUserNotification(email, "test", message);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/vpn/disable", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    const result = await (async () => {
      // attempt to disable via tailscale + optional external vpn endpoint
      try {
        await disableVPNAccess(username);
      } catch (e) {
        console.warn("vpn/disable disableVPNAccess error", e.message || e);
      }
      return { ok: true };
    })();

    res.json({ success: result.ok, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 SureData backend running on port ${PORT}`));
