// index.js — SureData Backend (Production-ready, Plan buckets migration + idempotent webhook + prune expired buckets)
// NOTE: This file is your original with only the migration + idempotent webhook additions and prune/auto-disable logic you requested.

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
// === ADDED HELPERS: plan-bucket utilities & migration helpers ===
// (these are the only additions beyond your original file)

// Compute total remaining MB from plans array
function computeTotalRemainingFromPlans(plans = []) {
  if (!Array.isArray(plans)) return 0;
  return plans.reduce((sum, p) => {
    const rem = p.remainingMB != null ? Number(p.remainingMB) : Number(p.dataLimitMB || p.dataLimit || 0);
    return sum + (isNaN(rem) ? 0 : rem);
  }, 0);
}

function isBucketExpired(bucket, now = new Date()) {
  if (!bucket) return false;
  if (!bucket.expiry) return false;
  try {
    const exp = new Date(bucket.expiry);
    return exp < now;
  } catch (e) {
    return false;
  }
}

/**
 * Prune expired or empty plan buckets from a user document (transactional).
 * - Removes buckets where expiry < now OR remainingMB <= 0
 * - Recomputes totalDataDisplay, planLimit, expiryDate
 * - If result has zero active buckets, sets vpnActive = false
 *
 * Returns { pruned: boolean, remainingCount, totalRemaining }
 */
async function pruneExpiredAndEmptyBuckets(userRef) {
  const now = new Date();
  const result = await db.runTransaction(async (t) => {
    const snap = await t.get(userRef);
    if (!snap.exists) {
      return { pruned: false, remainingCount: 0, totalRemaining: 0 };
    }
    const u = snap.data() || {};
    const plans = Array.isArray(u.plans) ? [...u.plans] : [];

    const keep = plans.filter((p) => {
      if (!p) return false;
      const remaining = Number(p.remainingMB != null ? p.remainingMB : p.dataLimitMB || p.dataLimit || 0);
      if (isNaN(remaining)) return false;
      if (remaining <= 0) return false;
      if (p.expiry) {
        try {
          const exp = new Date(p.expiry);
          if (exp < now) return false; // expired — drop it
        } catch (e) {
          // if expiry invalid, be conservative and keep
        }
      }
      return true;
    });

    const totalRemaining = computeTotalRemainingFromPlans(keep);
    const earliestExpiry = keep.length
      ? keep
          .map((p) => (p.expiry ? new Date(p.expiry) : null))
          .filter(Boolean)
          .sort((a, b) => a - b)[0]
      : null;

    const updates = {
      plans: keep,
      totalDataDisplay: totalRemaining,
      planLimit: totalRemaining,
      expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
      updatedAt: new Date().toISOString(),
    };

    // if no active buckets left, ensure vpnActive is false
    if (!keep.length) updates.vpnActive = false;

    t.update(userRef, updates);

    return { pruned: true, remainingCount: keep.length, totalRemaining };
  });

  // after transaction, if there are no remaining buckets, disable VPN access (best-effort) and notify
  try {
    if (result.remainingCount === 0) {
      // read user doc to get email / username for disabling (non-transactional)
      const userSnap = await userRef.get();
      const u = userSnap.exists ? userSnap.data() : {};
      const usernameOrEmail = u.email || u.uid || userRef.id;
      try {
        if (typeof disableVPNAccess === "function") {
          await disableVPNAccess(usernameOrEmail);
        } else {
          console.log("disableVPNAccess not defined; skipping external VPN disable.");
        }
      } catch (e) {
        console.warn("prune: disableVPNAccess error:", e.message || e);
      }
      // notify user
      if (u && u.email) {
        await sendUserNotification(
          u.email,
          "plan_exhausted",
          "🚫 Your plan has expired or been exhausted. Please purchase a new plan to re-enable VPN access."
        );
      }
    }
  } catch (notifyErr) {
    console.warn("prune: post-transaction notify/disable error:", notifyErr.message || notifyErr);
  }

  return result;
}

/**
 * Append a plan bucket to a user doc and recompute summary fields (transactional + dedupe).
 * - userRef: DocumentReference
 * - bucket: { name, dataLimitMB, remainingMB, purchasedAt, expiry, purchaseReference? }
 *
 * Returns { skipped: boolean, totalRemaining, plans }
 */
async function appendPlanBucketForUser(userRef, bucket) {
  // run a transaction: read current plans, check duplicates, write merged plans + totals atomically
  return db.runTransaction(async (t) => {
    const snap = await t.get(userRef);
    const u = snap.exists ? snap.data() : {};
    const currentPlansRaw = Array.isArray(u.plans) ? [...u.plans] : [];

    const now = new Date();

    // Filter out expired/empty plans for merging (we don't want expired buckets to roll into new purchase)
    const currentPlans = currentPlansRaw.filter((p) => {
      if (!p) return false;
      const remaining = Number(p.remainingMB != null ? p.remainingMB : p.dataLimitMB || p.dataLimit || 0);
      if (isNaN(remaining)) return false;
      if (remaining <= 0) return false;
      if (p.expiry) {
        try {
          const exp = new Date(p.expiry);
          if (exp < now) return false;
        } catch (e) {
          // if expiry invalid, keep
        }
      }
      return true;
    });

    // 1) If bucket has purchaseReference, skip if any existing plan already has same reference
    if (bucket.purchaseReference) {
      const found = currentPlans.some((p) => p && p.purchaseReference === bucket.purchaseReference);
      if (found) {
        const totalRemaining = computeTotalRemainingFromPlans(currentPlans);
        return { skipped: true, totalRemaining, plans: currentPlans };
      }
    }

    // 2) Additional conservative near-duplicate detection:
    // if an existing plan has same name + dataLimitMB + expiry + purchasedAt within 5 minutes, treat as duplicate
    const purchasedAtDate = bucket.purchasedAt ? new Date(bucket.purchasedAt).getTime() : null;
    const nearDup = currentPlans.some((p) => {
      try {
        if (!p) return false;
        const sameName = String(p.name || "") === String(bucket.name || "");
        const sameSize = Number(p.dataLimitMB || p.dataLimit || 0) === Number(bucket.dataLimitMB || 0);
        const sameExpiry = (p.expiry || "") === (bucket.expiry || "");
        let timeClose = false;
        if (p.purchasedAt && purchasedAtDate) {
          const diff = Math.abs(new Date(p.purchasedAt).getTime() - purchasedAtDate);
          timeClose = diff <= 5 * 60 * 1000; // within 5 minutes
        }
        return sameName && sameSize && sameExpiry && timeClose;
      } catch (e) {
        return false;
      }
    });
    if (nearDup) {
      const totalRemaining = computeTotalRemainingFromPlans(currentPlans);
      return { skipped: true, totalRemaining, plans: currentPlans };
    }

    // 3) Append bucket and recompute totals (we'll keep only non-expired plans + new bucket)
    const mergedPlans = [...currentPlans, bucket];
    const totalRemaining = computeTotalRemainingFromPlans(mergedPlans);
    const earliestExpiry = mergedPlans.length
      ? mergedPlans
          .map((p) => (p.expiry ? new Date(p.expiry) : null))
          .filter(Boolean)
          .sort((a, b) => a - b)[0]
      : null;

    // write merged plans + summary fields
    const updates = {
      plans: mergedPlans,
      totalDataDisplay: totalRemaining,
      planLimit: totalRemaining,
      expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
      updatedAt: new Date().toISOString(),
      vpnActive: true, // re-enable VPN on successful purchase
    };

    t.update(userRef, updates);
    return { skipped: false, totalRemaining, plans: mergedPlans };
  });
}

// Migrate legacy fields into plans[] (idempotent)
async function migrateLegacyToPlansIfNeeded(userRef, userData) {
  try {
    const existingPlans = Array.isArray(userData.plans) ? [...userData.plans] : [];
    const migrationBuckets = [];

    // migrate currentPlan if present and not represented in plans[]
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
          // attach lastPayment.reference if present — helps avoid duplicate later
          purchaseReference: userData.lastPayment?.reference || undefined,
        });
      }
    }

    // migrate pendingPlan if present and not already in plans[]
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
          purchaseReference: p.reference || p.purchaseReference || undefined,
        });
      }
    }

    if (migrationBuckets.length > 0) {
      const mergedPlans = [...existingPlans, ...migrationBuckets];
      const totalRemaining = computeTotalRemainingFromPlans(mergedPlans);
      const earliestExpiry = mergedPlans.length
        ? mergedPlans
            .map((p) => (p.expiry ? new Date(p.expiry) : null))
            .filter(Boolean)
            .sort((a, b) => a - b)[0]
        : null;

      // update user doc: set plans[], totalDataDisplay, clear legacy fields to avoid repeated migrations
      await userRef.update({
        plans: mergedPlans,
        totalDataDisplay: totalRemaining,
        planLimit: totalRemaining,
        expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
        pendingPlan: admin.firestore.FieldValue.delete(),
        currentPlan: admin.firestore.FieldValue.delete(),
        dataUsed: admin.firestore.FieldValue.delete(),
        updatedAt: new Date().toISOString(),
      });

      console.log(`Migrated ${migrationBuckets.length} legacy bucket(s) into plans[] for ${userRef.id}`);
      return { migrated: true, migrationBuckets };
    }
    return { migrated: false };
  } catch (e) {
    console.warn("Plan migration failed (non-fatal):", e.message || e);
    return { migrated: false, error: e.message || String(e) };
  }
}
// === END ADDED HELPERS ===
// ----------------------


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
// PAYSTACK WEBHOOK (UPDATED: idempotent + migration into plans[] + prune expired buckets)
// NOTE: changed to use txRef.create() to avoid race-duplicates
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

      // --- IDP: use create() to reserve the transaction doc atomically ---
      const txRef = db.collection("transactions").doc(reference);
      const now = new Date();

      try {
        // Attempt to create the transaction doc; fails if already exists.
        await txRef.create({
          email,
          reference,
          amount,
          status: "processing",
          receivedAt: now.toISOString(),
        });
        // created successfully — this process owns the reference now
      } catch (createErr) {
        // If the document already exists, read it and decide
        if (createErr && createErr.code && createErr.code === 6) {
          // Firestore gRPC ALREADY_EXISTS sometimes surfaces as code 6
          // fallthrough to read existing
        }
        const existing = await txRef.get();
        if (existing.exists) {
          const s = existing.data() || {};
          if (s.status === "success") {
            console.log(`🔁 Duplicate webhook detected for reference ${reference} — already processed.`);
            return res.sendStatus(200);
          }
          if (s.status === "processing") {
            console.log(`🔁 Webhook received while processing reference ${reference} — another worker is handling it. Skipping.`);
            return res.sendStatus(200);
          }
          // if previous status was "failed" or other, allow reprocessing below
          console.log(`ℹ️ Transaction doc exists with status='${s.status}', proceeding to reprocess: ${reference}`);
        } else {
          // unexpected, rethrow
          console.warn("txRef.create failed unexpectedly and existing doc not found:", createErr);
          // let later logic continue (we'll attempt to set processing below), but safer to retry set
          await txRef.set({
            email,
            reference,
            amount,
            status: "processing",
            receivedAt: now.toISOString(),
          }, { merge: true });
        }
      }

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
      let userData = snap.docs[0].data();

      // --- MIGRATE LEGACY FIELDS INTO plans[] IF NEEDED (idempotent) ---
      try {
        await migrateLegacyToPlansIfNeeded(userRef, userData);
        // re-read user data after possible migration
        const afterMig = await userRef.get();
        userData = afterMig.exists ? afterMig.data() : userData;
      } catch (e) {
        console.warn("Legacy migration error (non-fatal):", e.message || e);
      }

      // --- PRUNE expired/empty buckets BEFORE appending new purchase
      try {
        await pruneExpiredAndEmptyBuckets(userRef);
      } catch (e) {
        console.warn("prune before append failed (non-fatal):", e.message || e);
      }

      // Build new bucket (attach transaction reference for traceability)
      const newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + plan.days);

      const bucket = {
        name: plan.name,
        dataLimitMB: plan.dataLimit,
        remainingMB: plan.dataLimit,
        purchasedAt: now.toISOString(),
        expiry: newExpiry.toISOString(),
        purchaseReference: reference, // help trace / idempotency
      };

      // Append bucket and finalize transaction (transactional append prevents duplicates)
      try {
        const appendRes = await appendPlanBucketForUser(userRef, bucket);

        if (appendRes.skipped) {
          // mark tx as already-appended (safe)
          await txRef.set({
            status: "success",
            processedAt: new Date().toISOString(),
            plan: plan.name,
            totalAfter: appendRes.totalRemaining,
            note: "append_skipped_duplicate"
          }, { merge: true });

          console.log(`ℹ️ Append skipped (duplicate) for ${email} reference=${reference}`);
          return res.sendStatus(200);
        }

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
    const uRef = doc.ref;

    // prune expired/empty buckets first to ensure planLimit reflects only active buckets
    try {
      await pruneExpiredAndEmptyBuckets(uRef);
    } catch (e) {
      console.warn("disconnect: prune failed (non-fatal):", e.message || e);
    }

    // re-fetch user after prune
    const after = await uRef.get();
    const u = after.exists ? after.data() : {};

    const used = (u.dataUsed || 0) + data_used_mb;
    const over = used >= (u.planLimit || Infinity);
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();

    await uRef.update({
      dataUsed: used,
      vpnActive: !over && !expired,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    if (over || expired) {
      // disable both local VPN and tailscale device
      try {
        if (typeof disableVPNAccess === "function") {
          await disableVPNAccess(username);
        } else {
          console.log("disableVPNAccess not defined; skipping external VPN disable.");
        }
      } catch (e) {
        console.warn("disconnect: disableVPNAccess error:", e.message || e);
      }
      await sendUserNotification(
        username,
        "plan_exhausted",
        expired
          ? "Your plan has expired. Please renew."
          : "Your data limit has been exhausted. Please purchase a new plan to continue using VPN."
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
    const uRef = doc.ref;

    // prune expired/empty buckets first to ensure planLimit reflects only active buckets
    try {
      await pruneExpiredAndEmptyBuckets(uRef);
    } catch (e) {
      console.warn("update-usage: prune failed (non-fatal):", e.message || e);
    }

    // re-fetch user after prune
    const after = await uRef.get();
    const u = after.exists ? after.data() : {};

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

    await uRef.update({
      dataUsed: used,
      vpnActive: !over && !expired,
      updatedAt: new Date().toISOString(),
    });

    if (over || expired) {
      try {
        if (typeof disableVPNAccess === "function") {
          await disableVPNAccess(username);
        } else {
          console.log("disableVPNAccess not defined; skipping external VPN disable.");
        }
      } catch (e) {
        console.warn("update-usage: disableVPNAccess error:", e.message || e);
      }
      await sendUserNotification(
        username,
        "plan_exhausted",
        over
          ? "🚫 Your data plan has been exhausted. Please purchase a new plan to continue using VPN."
          : "⌛ Your plan has expired. Please renew to re-enable VPN."
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
      const userRef = doc.ref;

      // Prune expired/empty buckets for each user
      try {
        const pr = await pruneExpiredAndEmptyBuckets(userRef);
        // if pruning left zero active plans, increment disabled and ensure VPN disabled
        if (pr.remainingCount === 0) {
          disabled++;
        }
      } catch (e) {
        console.warn(`cron prune error for ${doc.id}:`, e.message || e);
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
