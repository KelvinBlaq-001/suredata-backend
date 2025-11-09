// index.js — SureData Backend (Production-ready, Plan buckets, Idempotent webhook, auto-assign disabled)

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
  console.warn(
    "⚠️ ADMIN_API_KEY not set — node admin endpoints will be accessible without admin key. Set ADMIN_API_KEY to secure them."
  );
}
function requireAdmin(req, res, next) {
  if (!adminApiKey) return next(); // allow in dev
  const key = req.headers["x-admin-key"];
  if (!key || key !== adminApiKey) {
    return res
      .status(401)
      .json({ error: "Unauthorized (missing or invalid x-admin-key)" });
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
// TAILSCALE HELPERS (best-effort)
function _tailscaleAuthHeader() {
  const apiKey = process.env.TAILSCALE_API_KEY || "";
  const token = Buffer.from(`${apiKey}:`).toString("base64");
  return `Basic ${token}`;
}
const BASE_URL = process.env.TAILSCALE_API_BASE || "https://api.tailscale.com/api/v2";
const TAILNET = process.env.TAILSCALE_TAILNET || null;

async function tailscaleListDevices() {
  try {
    if (!TAILNET) throw new Error("TAILSCALE_TAILNET not set");
    const url = `${BASE_URL}/tailnet/${encodeURIComponent(TAILNET)}/devices`;
    const res = await fetch(url, {
      method: "GET",
      headers: { Authorization: _tailscaleAuthHeader() },
    });
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
    if (!deviceId) throw new Error("deviceId required");
    if (!TAILNET) {
      console.warn("No TAILNET set — skipping tailscaleEnableDevice");
      return { ok: false, error: "no-tailnet" };
    }

    // Attempts (best-effort)
    const candidates = [
      `${BASE_URL}/tailnet/${encodeURIComponent(TAILNET)}/devices/${encodeURIComponent(deviceId)}`,
      `${BASE_URL}/device/${encodeURIComponent(deviceId)}`,
      `${BASE_URL}/devices/${encodeURIComponent(deviceId)}`,
    ];

    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: "PATCH",
          headers: {
            Authorization: _tailscaleAuthHeader(),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({}), // no-op
        });
        if (res.ok || res.status === 204) {
          return { ok: true, url };
        } else {
          const text = await res.text();
          console.warn(`tailscaleEnableDevice attempt ${url} -> ${res.status} ${text}`);
        }
      } catch (e) {
        console.warn("tailscaleEnableDevice inner attempt failed:", e.message || e);
      }
    }

    console.warn("tailscaleEnableDevice: no supported enable endpoint found");
    return { ok: false, error: "no-endpoint" };
  } catch (err) {
    console.warn("tailscaleEnableDevice error:", err.message || err);
    return { ok: false, error: err.message };
  }
}

async function tailscaleDisableDevice(deviceId) {
  try {
    if (!deviceId) throw new Error("deviceId required");

    const candidates = [];
    if (TAILNET) {
      candidates.push(`${BASE_URL}/tailnet/${encodeURIComponent(TAILNET)}/devices/${encodeURIComponent(deviceId)}`);
    }
    candidates.push(`${BASE_URL}/devices/${encodeURIComponent(deviceId)}`);
    candidates.push(`${BASE_URL}/device/${encodeURIComponent(deviceId)}`);

    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: "DELETE",
          headers: {
            Authorization: _tailscaleAuthHeader(),
          },
        });
        if (res.ok || res.status === 204) {
          return { ok: true, url, status: res.status };
        } else {
          const text = await res.text();
          console.warn(`tailscaleDisableDevice attempt ${url} -> ${res.status} ${text}`);
          if (res.status >= 200 && res.status < 300) {
            return { ok: true, url, status: res.status };
          }
        }
      } catch (e) {
        console.warn("tailscaleDisableDevice inner attempt failed:", e.message || e);
      }
    }

    return { ok: false, error: "no-supported-endpoint" };
  } catch (err) {
    console.warn("tailscaleDisableDevice error:", err.message || err);
    return { ok: false, error: err.message };
  }
}
// ----------------------

// ----------------------
// Node management helpers (Firestore: tailscale_nodes)
async function upsertNode(node) {
  if (!node.deviceId) {
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
    await docRef.set(
      {
        deviceId: node.deviceId,
        hostname: node.hostname || null,
        ip: node.ip || null,
        user: node.user || null,
        assignedTo: node.assignedTo || null,
        status: node.status || "free",
        load: node.load || 0.0,
        online: typeof node.online === "boolean" ? node.online : true,
        lastChecked: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return node.deviceId;
  }
}

async function pickBestNode() {
  try {
    const q = await db
      .collection("tailscale_nodes")
      .where("online", "==", true)
      .where("status", "==", "free")
      .orderBy("load", "asc")
      .limit(1)
      .get();
    if (q.empty) return null;
    return q.docs[0];
  } catch (err) {
    console.warn("pickBestNode error:", err.message || err);
    return null;
  }
}

async function assignNodeToUser(nodeDocRef, userIdOrEmail) {
  const doc = await nodeDocRef.get();
  if (!doc.exists) throw new Error("node missing");
  const data = doc.data() || {};
  const newLoad = (data.load || 0) + 0.05;
  await nodeDocRef.update({
    status: "in_use",
    assignedTo: userIdOrEmail,
    load: newLoad,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
  return {
    ok: true,
    deviceId: doc.id,
    nodeData: { ...data, load: newLoad, assignedTo: userIdOrEmail },
  };
}

async function releaseNode(nodeDocRef) {
  const doc = await nodeDocRef.get();
  if (!doc.exists) return { ok: false, reason: "missing" };
  const data = doc.data() || {};
  const newLoad = Math.max((data.load || 0) - 0.05, 0);
  await nodeDocRef.update({
    status: "free",
    assignedTo: null,
    load: newLoad,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { ok: true };
}

async function setNodeOnline(nodeDocRef, online) {
  await nodeDocRef.update({
    online,
    lastChecked: admin.firestore.FieldValue.serverTimestamp(),
  });
}
// ----------------------

// ----------------------
// Plan bucket helpers (canonical model)

function computeTotalRemainingFromPlans(plans = []) {
  if (!Array.isArray(plans)) return 0;
  return plans.reduce((sum, p) => {
    const rem = p.remainingMB != null ? Number(p.remainingMB) : Number(p.dataLimitMB || 0);
    return sum + (isNaN(rem) ? 0 : rem);
  }, 0);
}

function canonicalIdentifierFromEmailOrUid(emailOrUid) {
  if (!emailOrUid) return null;
  return String(emailOrUid).toLowerCase();
}

async function appendPlanBucketForUser(userRef, bucket) {
  // Append bucket using arrayUnion (safe for many concurrent writes).
  await userRef.update({
    plans: admin.firestore.FieldValue.arrayUnion(bucket),
    updatedAt: new Date().toISOString(),
  });

  // Recompute summary fields
  const snap = await userRef.get();
  const u = snap.exists ? snap.data() : {};
  const plans = Array.isArray(u.plans) ? u.plans : [];
  const totalRemaining = computeTotalRemainingFromPlans(plans);
  const earliestExpiry = plans.length
    ? plans
        .map((p) => (p.expiry ? new Date(p.expiry) : null))
        .filter(Boolean)
        .sort((a, b) => a - b)[0]
    : null;

  await userRef.update({
    totalDataDisplay: totalRemaining,
    planLimit: totalRemaining,
    expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
    updatedAt: new Date().toISOString(),
  });

  return { totalRemaining, plans };
}

/**
 * Consume usageMB from user's plan buckets (earliest expiry first).
 * Returns { exhausted, remainingNotConsumedMB, totalRemaining, updatedPlans }
 */
async function consumeFromPlanBuckets(userRef, usageMB) {
  const snap = await userRef.get();
  if (!snap.exists) return { error: "user_not_found" };

  const now = new Date();
  const u = snap.data() || {};
  let plans = Array.isArray(u.plans) ? [...u.plans] : [];

  // Normalize
  plans = plans.map((p) => ({
    name: p.name,
    dataLimitMB: Number(p.dataLimitMB || p.dataLimit || 0),
    remainingMB: p.remainingMB != null ? Number(p.remainingMB) : Number(p.dataLimitMB || p.dataLimit || 0),
    expiry: p.expiry || p.expiryDate || null,
    purchasedAt: p.purchasedAt || null,
  }));

  // Remove expired / empty
  plans = plans.filter((p) => {
    if (!p.expiry) return (p.remainingMB || 0) > 0;
    const exp = new Date(p.expiry);
    return exp > now && (p.remainingMB || 0) > 0;
  });

  // Sort earliest expiry first (null expiry last)
  plans.sort((a, b) => {
    if (!a.expiry && !b.expiry) return 0;
    if (!a.expiry) return 1;
    if (!b.expiry) return -1;
    return new Date(a.expiry) - new Date(b.expiry);
  });

  let remainingToConsume = Number(usageMB || 0);
  for (let i = 0; i < plans.length && remainingToConsume > 0; i++) {
    const p = plans[i];
    const avail = Math.max(Number(p.remainingMB || 0), 0);
    const take = Math.min(avail, remainingToConsume);
    p.remainingMB = avail - take;
    remainingToConsume -= take;
  }

  // Remove emptied buckets
  plans = plans.filter((p) => Number(p.remainingMB || 0) > 0);

  const totalRemaining = computeTotalRemainingFromPlans(plans);
  const earliestExpiry = plans.length
    ? plans
        .map((p) => (p.expiry ? new Date(p.expiry) : null))
        .filter(Boolean)
        .sort((a, b) => a - b)[0]
    : null;

  await userRef.update({
    plans,
    totalDataDisplay: totalRemaining,
    planLimit: totalRemaining,
    expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
    updatedAt: new Date().toISOString(),
  });

  return {
    exhausted: remainingToConsume > 0,
    remainingNotConsumedMB: remainingToConsume,
    totalRemaining,
    updatedPlans: plans,
  };
}

async function purgeExpiredBucketsForUser(userRef) {
  const snap = await userRef.get();
  if (!snap.exists) return { totalRemaining: 0 };
  const now = new Date();
  const u = snap.data() || {};
  let plans = Array.isArray(u.plans) ? [...u.plans] : [];
  plans = plans.filter((p) => {
    if (!p.expiry) return (p.remainingMB || p.dataLimitMB || p.dataLimit || 0) > 0;
    const exp = new Date(p.expiry);
    return exp > now && (p.remainingMB || p.dataLimitMB || p.dataLimit || 0) > 0;
  });

  const totalRemaining = computeTotalRemainingFromPlans(plans);
  const earliestExpiry = plans.length
    ? plans
        .map((p) => (p.expiry ? new Date(p.expiry) : null))
        .filter(Boolean)
        .sort((a, b) => a - b)[0]
    : null;

  await userRef.update({
    plans,
    totalDataDisplay: totalRemaining,
    planLimit: totalRemaining,
    expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
    updatedAt: new Date().toISOString(),
  });

  return { totalRemaining, plans };
}
// ----------------------

// ----------------------------
// PAYSTACK WEBHOOK (idempotent + migration -> plans[])
// ----------------------------
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;
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

      if (process.env.NODE_ENV !== "production" && receivedHash === "test-bypass") {
        console.log("🧪 Paystack test-bypass active");
      } else if (computedHash !== receivedHash) {
        console.log("⚠️ Invalid Paystack signature");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      if (event.event !== "charge.success") return res.sendStatus(200);

      const data = event.data;
      const reference = data.reference;
      const amount = data.amount / 100; // amount in Naira
      const email = (data.customer?.email || "").toLowerCase();

      // Idempotency: check transactions doc for this reference
      const txRef = db.collection("transactions").doc(reference);
      const txSnap = await txRef.get();
      if (txSnap.exists && txSnap.data() && txSnap.data().status === "success") {
        console.log(`🔁 Duplicate webhook for reference ${reference} — already processed.`);
        return res.sendStatus(200);
      }

      // Mark transaction as processing (so concurrent webhook attempts won't double-process)
      const now = new Date();
      await txRef.set({
        email,
        reference,
        amount,
        status: "processing",
        createdAt: now.toISOString(),
      }, { merge: true });

      // Match plan by amount (MB)
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

      // Find user
      const usersRef = db.collection("users");
      const snap = await usersRef.where("email", "==", email).limit(1).get();
      if (snap.empty) {
        console.log(`❌ User not found for email ${email}`);
        await txRef.set({
          status: "user_not_found",
          timestamp: new Date().toISOString(),
        }, { merge: true });
        return res.sendStatus(200);
      }

      const userRef = snap.docs[0].ref;
      const userData = snap.docs[0].data();

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

      // NOTE: automatic node assignment intentionally REMOVED to avoid the errors you saw.
      return res.sendStatus(200);
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
      if (u.plans && u.plans.length) withPlan++;
    });

    res.json({ total, active, expired, withPlan });
  } catch (err) {
    console.error("admin/summary error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// Tailscale & Node Endpoints (manual admin control)
app.post("/tailscale/seed-nodes", requireAdmin, async (req, res) => {
  try {
    const nodes = req.body.nodes;
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

app.post("/tailscale/sync-from-api", requireAdmin, async (req, res) => {
  try {
    const devices = await tailscaleListDevices();
    const upserts = [];
    for (const d of devices) {
      const deviceId = d.id || d.node_id || d.key || d.idString || d.id?.toString();
      const hostname = d.hostname || d.name || null;
      const ip = (d.allAddresses && d.allAddresses[0]) || d.addresses?.[0] || null;
      const user = d.user || d.userName || null;
      const online = d.online !== undefined ? !!d.online : true;
      const load = 0.0;
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

// Manual auto-assign endpoint (admin-only) still available
app.post("/vpn/node/auto-assign", requireAdmin, async (req, res) => {
  try {
    const { email, uid } = req.body;
    const rawIdentifier = uid || email;
    if (!rawIdentifier) return res.status(400).json({ error: "email or uid required" });

    const userIdentifier = canonicalIdentifierFromEmailOrUid(rawIdentifier);

    const nodeDoc = await pickBestNode();
    if (!nodeDoc) {
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

// Revoke node (admin)
app.post("/vpn/node/revoke", requireAdmin, async (req, res) => {
  try {
    const { email, uid } = req.body;
    const rawIdentifier = uid || email;
    if (!rawIdentifier) return res.status(400).json({ error: "email or uid required" });

    const userIdentifier = canonicalIdentifierFromEmailOrUid(rawIdentifier);
    const sessionRef = db.collection("vpn_sessions").doc(userIdentifier);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists) return res.status(404).json({ error: "No active session for user" });

    const session = sessionSnap.data() || {};
    const nodeId = session.nodeId;
    if (nodeId) {
      const nodeRef = db.collection("tailscale_nodes").doc(nodeId);
      try {
        const tailscaleRes = await tailscaleDisableDevice(nodeId);
        console.log("tailscaleDisableDevice result:", tailscaleRes);
      } catch (err) {
        console.warn("tailscaleDisableDevice failed:", err?.message || err);
      }
      try {
        await releaseNode(nodeRef);
      } catch (err) {
        console.warn("releaseNode failed:", err?.message || err);
      }
    }

    await sessionRef.update({ active: false, revokedAt: new Date().toISOString() });

    try {
      let userDocSnap = null;
      if (uid) {
        userDocSnap = await db.collection("users").doc(uid).get();
      }
      if (!userDocSnap || !userDocSnap.exists) {
        const q = await db.collection("users").where("email", "==", email).limit(1).get();
        if (!q.empty) userDocSnap = q.docs[0];
      }
      if (userDocSnap && userDocSnap.exists) {
        await userDocSnap.ref.update({
          vpnActive: false,
          revokedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
      } else {
        console.warn("User doc not found while revoking for", userIdentifier);
      }
    } catch (e) {
      console.warn("Failed to update user doc during revoke:", e?.message || e);
    }

    res.json({ success: true, revoked: true, nodeId: nodeId || null });
  } catch (err) {
    console.error("/vpn/node/revoke error:", err?.message || err);
    res.status(500).json({ error: err?.message || String(err) });
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
// VPN session handlers (connect/disconnect/update-usage)
async function disableVPNAccess(usernameOrEmail) {
  try {
    let userDoc = null;
    const byUid = await db.collection("users").doc(usernameOrEmail).get();
    if (byUid.exists) userDoc = byUid;
    if (!userDoc) {
      const q = await db.collection("users").where("email", "==", usernameOrEmail).limit(1).get();
      if (!q.empty) userDoc = q.docs[0];
    }
    if (userDoc) {
      await userDoc.ref.update({
        vpnActive: false,
        revokedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    const sessionRef = db.collection("vpn_sessions").doc(usernameOrEmail);
    const s = await sessionRef.get();
    if (s.exists) {
      const sess = s.data() || {};
      if (sess.nodeId) {
        try {
          await tailscaleDisableDevice(sess.nodeId);
        } catch (e) {
          console.warn("disableVPNAccess tailscaleDisableDevice failed", e.message || e);
        }
        try {
          await releaseNode(db.collection("tailscale_nodes").doc(sess.nodeId));
        } catch (e) {
          console.warn("disableVPNAccess releaseNode failed", e.message || e);
        }
      }
      await sessionRef.update({ active: false, revokedAt: new Date().toISOString() });
    }
  } catch (err) {
    console.warn("disableVPNAccess error:", err.message || err);
  }
}

app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    const email = String(username).toLowerCase();
    const snap = await db.collection("users").where("email", "==", email).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const docRef = snap.docs[0].ref;
    await docRef.update({
      vpnActive: true,
      vpnIP: vpn_ip,
      lastConnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    try {
      const user = snap.docs[0].data();
      if (user && user.vpnDeviceId) {
        await tailscaleEnableDevice(user.vpnDeviceId);
      } else {
        // Auto-assign on connect intentionally DISABLED (to avoid previous errors).
        console.log(`Auto-assign on connect disabled for ${email}.`);
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
    if (!username) return res.status(400).json({ error: "username required" });

    const email = String(username).toLowerCase();
    const snap = await db.collection("users").where("email", "==", email).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const userRef = snap.docs[0].ref;
    const consumeRes = await consumeFromPlanBuckets(userRef, Number(data_used_mb || 0));
    const over = consumeRes.exhausted;
    const expired = consumeRes.totalRemaining <= 0;

    await userRef.update({
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      vpnActive: !over && !expired,
    });

    if (over || expired) {
      await disableVPNAccess(email);
      await sendUserNotification(
        email,
        "plan_exhausted",
        expired ? "Your plan has expired. Please renew." : "Your data limit has been exhausted."
      );
    }

    res.json({ success: true, consumeResult: consumeRes });
  } catch (err) {
    console.error("Disconnect error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/vpn/session/update-usage", async (req, res) => {
  try {
    const { username, usage_mb = 0 } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    const email = String(username).toLowerCase();
    const snap = await db.collection("users").where("email", "==", email).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const userRef = snap.docs[0].ref;
    const prevTotal = snap.docs[0].data().totalDataDisplay || 0;

    const consumeRes = await consumeFromPlanBuckets(userRef, Number(usage_mb || 0));
    const totalRemaining = consumeRes.totalRemaining || 0;
    const percent = prevTotal > 0 ? ((prevTotal - totalRemaining) / (prevTotal || 1)) * 100 : 0;

    if (percent >= 90 && percent < 100) {
      await sendUserNotification(
        email,
        "plan_near_limit",
        `⚠️ You've used ${Math.min(100, Math.round(percent))}% of your plan.`
      );
    }

    const over = consumeRes.exhausted;
    const expired = totalRemaining <= 0;

    await userRef.update({
      updatedAt: new Date().toISOString(),
      vpnActive: !over && !expired,
    });

    if (over || expired) {
      await disableVPNAccess(email);
      await sendUserNotification(
        email,
        "plan_exhausted",
        over ? "🚫 Your data plan has been exhausted." : "⌛ Your plan has expired."
      );
    }

    res.json({ success: true, consumeResult: consumeRes });
  } catch (err) {
    console.error("Usage update error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// CRON JOBS
app.get("/cron/expire-check", async (req, res) => {
  try {
    console.log("⏰ Checking expired users (bucket-based)...");
    const usersSnapshot = await db.collection("users").get();
    let disabled = 0;

    for (const doc of usersSnapshot.docs) {
      const u = doc.data();
      const purgeRes = await purgeExpiredBucketsForUser(doc.ref);
      const totalRemaining = purgeRes.totalRemaining || 0;

      if (totalRemaining <= 0) {
        await disableVPNAccess(u.email || u.username || doc.id);
        await doc.ref.update({ vpnActive: false, updatedAt: new Date().toISOString() });
        disabled++;
        console.log(`🚫 Disabled user due to no remaining buckets: ${u.email || doc.id}`);
      }
    }

    res.json({ message: `✅ Expire check done: ${disabled} disabled.` });
  } catch (err) {
    console.error("❌ Expire check error:", err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Tailscale sync (admin)
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

    try {
      await disableVPNAccess(username);
    } catch (e) {
      console.warn("vpn/disable disableVPNAccess error", e.message || e);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 SureData backend running on port ${PORT}`));
