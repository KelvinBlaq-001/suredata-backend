// index.js — SureData Backend (Production-ready, Plan buckets migration + idempotent webhook + prune/consume + progress fields)
// Full file: includes totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent for UI sync.

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

/**
 * sendThresholdNotifications(userRef, email, percent)
 * - Sends configured thresholds (70, 98) once per purchase / until reset.
 * - Persists sent thresholds in users.notificationsSentThresholds using arrayUnion.
 */
async function sendThresholdNotifications(userRef, email, percent) {
  if (!email) return;
  try {
    const snap = await userRef.get();
    if (!snap.exists) return;
    const u = snap.data() || {};
    const sent = Array.isArray(u.notificationsSentThresholds) ? u.notificationsSentThresholds : [];
    const thresholds = [70, 98];

    const toSend = thresholds.filter((t) => percent >= t && !sent.includes(t));
    for (const t of toSend) {
      let message = `⚠️ You've used ${t}% of your plan.`;
      if (t === 98) {
        message = `⚠️ You're at ${t}% — your data is almost exhausted. Please prepare to renew.`;
      } else if (t === 70) {
        message = `⚠️ You've used ${t}% of your plan. Consider monitoring your usage.`;
      }
      await sendUserNotification(email, "plan_near_limit", message);
    }

    if (toSend.length) {
      // mark them as sent
      await userRef.update({
        notificationsSentThresholds: admin.firestore.FieldValue.arrayUnion(...toSend),
      });
    }
  } catch (e) {
    console.warn("sendThresholdNotifications error:", e.message || e);
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
// === ADDED HELPERS: plan-bucket utilities, status + consumption + migration helpers + progress fields ===
// ----------------------

/**
 * computeTotalRemainingFromPlans(plans, options)
 * - options.onlyActive (default true) - sums remainingMB/limit only for buckets considered active
 */
function computeTotalRemainingFromPlans(plans = [], options = { onlyActive: true }) {
  if (!Array.isArray(plans)) return 0;
  const onlyActive = options.onlyActive !== undefined ? options.onlyActive : true;
  return plans.reduce((sum, p) => {
    if (!p) return sum;
    if (onlyActive && String((p.status || "active")).toLowerCase() !== "active") return sum;
    const rem = p.remainingMB != null ? Number(p.remainingMB) : Number(p.dataLimitMB || p.dataLimit || 0);
    return sum + (isNaN(rem) ? 0 : rem);
  }, 0);
}

/**
 * computeTotalAllocatedFromPlans(plans, options)
 * - sums original dataLimitMB for buckets (only active if onlyActive true)
 */
function computeTotalAllocatedFromPlans(plans = [], options = { onlyActive: true }) {
  if (!Array.isArray(plans)) return 0;
  const onlyActive = options.onlyActive !== undefined ? options.onlyActive : true;
  return plans.reduce((sum, p) => {
    if (!p) return sum;
    if (onlyActive && String((p.status || "active")).toLowerCase() !== "active") return sum;
    const alloc = Number(p.dataLimitMB || p.dataLimit || 0);
    return sum + (isNaN(alloc) ? 0 : alloc);
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
 * computeProgressFields(plans)
 * - returns { totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent }
 * - only counts 'active' buckets
 */
function computeProgressFields(plans = []) {
  const totalRemainingMB = computeTotalRemainingFromPlans(plans, { onlyActive: true });
  const totalAllocatedMB = computeTotalAllocatedFromPlans(plans, { onlyActive: true });
  const totalUsedMB = Math.max(0, totalAllocatedMB - totalRemainingMB);
  const progressPercent = totalAllocatedMB > 0 ? Math.min(100, (totalUsedMB / totalAllocatedMB) * 100) : 0;
  // round to 1 decimal to keep UI tidy
  const progressRounded = Math.round(progressPercent * 10) / 10;
  return {
    totalAllocatedMB,
    totalRemainingMB,
    totalUsedMB,
    progressPercent: progressRounded,
  };
}

/**
 * normalizeBucketStatuses(userRef)
 * - Transactionally walks plans[] and sets status on each bucket:
 *    - 'expired' if expiry < now
 *    - 'exhausted' if remainingMB <= 0
 *    - otherwise 'active'
 * - Recomputes totals based on active buckets only and updates planLimit/totalDataDisplay/expiryDate
 * - ALSO writes totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent (for UI)
 */
async function normalizeBucketStatuses(userRef) {
  const now = new Date();
  return db.runTransaction(async (t) => {
    const snap = await t.get(userRef);
    if (!snap.exists) return { updated: false, remainingCount: 0, totalRemaining: 0 };
    const u = snap.data() || {};
    const plansRaw = Array.isArray(u.plans) ? [...u.plans] : [];

    const normalized = plansRaw.map((p) => {
      if (!p) return p;
      const copy = { ...p };
      const remaining = Number(copy.remainingMB != null ? copy.remainingMB : copy.dataLimitMB || copy.dataLimit || 0);
      let expired = false;
      if (copy.expiry) {
        try {
          const exp = new Date(copy.expiry);
          if (exp < now) expired = true;
        } catch (e) {
          // ignore
        }
      }
      if (expired) {
        copy.status = "expired";
      } else if (isNaN(remaining) || remaining <= 0) {
        copy.status = "exhausted";
        copy.remainingMB = Math.max(isNaN(remaining) ? 0 : remaining, 0);
      } else {
        copy.status = copy.status ? copy.status : "active";
      }
      return copy;
    });

    const { totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent } = computeProgressFields(normalized);
    const activePlans = normalized.filter((p) => p && String(p.status).toLowerCase() === "active");

    const earliestExpiry = activePlans.length
      ? activePlans
          .map((p) => (p.expiry ? new Date(p.expiry) : null))
          .filter(Boolean)
          .sort((a, b) => a - b)[0]
      : null;

    const updates = {
      plans: normalized,
      // keep old fields for compatibility
      totalDataDisplay: totalRemainingMB,
      planLimit: totalRemainingMB,
      // new explicit fields for UI clarity
      totalAllocatedMB,
      totalRemainingMB,
      totalUsedMB,
      progressPercent,
      expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
      updatedAt: new Date().toISOString(),
    };

    if (!activePlans.length) updates.vpnActive = false;

    t.update(userRef, updates);

    return { updated: true, remainingCount: activePlans.length, totalRemaining: totalRemainingMB };
  });
}

/**
 * consumeUsageFromBuckets(userRef, usageMb)
 * - Deducts usageMb from active plan buckets FIFO by earliest expiry (transactional)
 * - Updates bucket.remainingMB, sets bucket.status='exhausted' when depleted
 * - Increments user.dataUsed by consumed amount
 * - Recomputes totals based on active buckets
 * - Writes progress fields for UI
 * Returns { consumed: number, stillNeeded: number, totalRemaining, remainingActiveBuckets, totalAllocatedMB, totalUsedMB, progressPercent }
 */
async function consumeUsageFromBuckets(userRef, usageMb) {
  if (!usageMb || usageMb <= 0) return { consumed: 0, stillNeeded: 0, totalRemaining: 0, remainingActiveBuckets: 0, totalAllocatedMB: 0, totalUsedMB: 0, progressPercent: 0 };

  return db.runTransaction(async (t) => {
    const snap = await t.get(userRef);
    if (!snap.exists) return { consumed: 0, stillNeeded: usageMb, totalRemaining: 0, remainingActiveBuckets: 0, totalAllocatedMB: 0, totalUsedMB: 0, progressPercent: 0 };
    const u = snap.data() || {};
    const plansRaw = Array.isArray(u.plans) ? [...u.plans] : [];

    const now = new Date();
    // Normalize existing plans locally
    const normalized = plansRaw.map((p) => {
      if (!p) return p;
      const copy = { ...p };
      const remaining = Number(copy.remainingMB != null ? copy.remainingMB : copy.dataLimitMB || copy.dataLimit || 0);
      let expired = false;
      if (copy.expiry) {
        try {
          const exp = new Date(copy.expiry);
          if (exp < now) expired = true;
        } catch (e) {}
      }
      if (expired) {
        copy.status = "expired";
      } else if (isNaN(remaining) || remaining <= 0) {
        copy.status = "exhausted";
        copy.remainingMB = Math.max(isNaN(remaining) ? 0 : remaining, 0);
      } else {
        copy.status = copy.status ? copy.status : "active";
      }
      return copy;
    });

    // Sort active plans FIFO by expiry then purchasedAt
    const activePlans = normalized
      .map((p, idx) => ({ p, idx }))
      .filter((x) => x.p && String(x.p.status).toLowerCase() === "active")
      .sort((a, b) => {
        const aExp = a.p.expiry ? new Date(a.p.expiry).getTime() : Infinity;
        const bExp = b.p.expiry ? new Date(b.p.expiry).getTime() : Infinity;
        if (aExp !== bExp) return aExp - bExp;
        const aPurchased = a.p.purchasedAt ? new Date(a.p.purchasedAt).getTime() : 0;
        const bPurchased = b.p.purchasedAt ? new Date(b.p.purchasedAt).getTime() : 0;
        return aPurchased - bPurchased;
      });

    let remainingToConsume = Number(usageMb || 0);
    let consumed = 0;

    for (const item of activePlans) {
      if (remainingToConsume <= 0) break;
      const idx = item.idx;
      const bucket = normalized[idx];
      const bucketRemaining = Number(bucket.remainingMB != null ? bucket.remainingMB : bucket.dataLimitMB || bucket.dataLimit || 0);
      if (isNaN(bucketRemaining) || bucketRemaining <= 0) {
        bucket.remainingMB = 0;
        bucket.status = "exhausted";
        continue;
      }
      const delta = Math.min(bucketRemaining, remainingToConsume);
      bucket.remainingMB = Math.max(bucketRemaining - delta, 0);
      remainingToConsume -= delta;
      consumed += delta;
      if (bucket.remainingMB <= 0) {
        bucket.status = "exhausted";
      } else {
        bucket.status = "active";
      }
    }

    // Update user's dataUsed historical counter
    const prevDataUsed = Number(u.dataUsed || 0);
    const newDataUsed = prevDataUsed + consumed;

    // Compute progress and totals after mutation
    const { totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent } = computeProgressFields(normalized);
    const activeAfter = normalized.filter((p) => p && String(p.status).toLowerCase() === "active");
    const earliestExpiry = activeAfter.length
      ? activeAfter
          .map((p) => (p.expiry ? new Date(p.expiry) : null))
          .filter(Boolean)
          .sort((a, b) => a - b)[0]
      : null;

    const updates = {
      plans: normalized,
      dataUsed: newDataUsed,
      // compatibility fields
      totalDataDisplay: totalRemainingMB,
      planLimit: totalRemainingMB,
      // explicit progress fields
      totalAllocatedMB,
      totalRemainingMB,
      totalUsedMB,
      progressPercent,
      expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
      updatedAt: new Date().toISOString(),
    };

    if (activeAfter.length === 0) updates.vpnActive = false;

    t.update(userRef, updates);

    return {
      consumed,
      stillNeeded: Math.max(0, remainingToConsume),
      totalRemaining: totalRemainingMB,
      remainingActiveBuckets: activeAfter.length,
      totalAllocatedMB,
      totalUsedMB,
      progressPercent
    };
  });
}

/**
 * Append a plan bucket to a user doc and recompute summary fields (transactional + dedupe).
 * - New bucket will have status 'active'
 * - Writes progress fields for UI: totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent
 */
async function appendPlanBucketForUser(userRef, bucket) {
  return db.runTransaction(async (t) => {
    const snap = await t.get(userRef);
    const u = snap.exists ? snap.data() : {};
    const currentPlansRaw = Array.isArray(u.plans) ? [...u.plans] : [];
    const now = new Date();

    // Normalize existing plans locally
    const normalized = currentPlansRaw.map((p) => {
      if (!p) return p;
      const copy = { ...p };
      const remaining = Number(copy.remainingMB != null ? copy.remainingMB : copy.dataLimitMB || copy.dataLimit || 0);
      let expired = false;
      if (copy.expiry) {
        try {
          const exp = new Date(copy.expiry);
          if (exp < now) expired = true;
        } catch (e) {}
      }
      if (expired) {
        copy.status = "expired";
      } else if (isNaN(remaining) || remaining <= 0) {
        copy.status = "exhausted";
        copy.remainingMB = Math.max(isNaN(remaining) ? 0 : remaining, 0);
      } else {
        copy.status = copy.status ? copy.status : "active";
      }
      return copy;
    });

    // Dedupe by purchaseReference across all plans (history included)
    if (bucket.purchaseReference) {
      const existsRef = normalized.some((p) => p && p.purchaseReference === bucket.purchaseReference);
      if (existsRef) {
        const { totalRemainingMB } = computeProgressFields(normalized);
        return { skipped: true, totalRemaining: totalRemainingMB, plans: normalized };
      }
    }

    // Near-duplicate detection among active plans
    const activePlans = normalized.filter((p) => p && String(p.status).toLowerCase() === "active");
    const purchasedAtDate = bucket.purchasedAt ? new Date(bucket.purchasedAt).getTime() : null;
    const nearDup = activePlans.some((p) => {
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
      const { totalRemainingMB } = computeProgressFields(normalized);
      return { skipped: true, totalRemaining: totalRemainingMB, plans: normalized };
    }

    // Prepare new bucket and append
    const newBucket = { ...bucket, status: "active" };
    const mergedPlans = [...normalized, newBucket];

    const { totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent } = computeProgressFields(mergedPlans);
    const activeAfter = mergedPlans.filter((p) => p && String(p.status).toLowerCase() === "active");
    const earliestExpiry = activeAfter.length
      ? activeAfter
          .map((p) => (p.expiry ? new Date(p.expiry) : null))
          .filter(Boolean)
          .sort((a, b) => a - b)[0]
      : null;

    const updates = {
      plans: mergedPlans,
      // compatibility
      totalDataDisplay: totalRemainingMB,
      planLimit: totalRemainingMB,
      // explicit progress
      totalAllocatedMB,
      totalRemainingMB,
      totalUsedMB,
      progressPercent,
      expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
      updatedAt: new Date().toISOString(),
      vpnActive: true,
      // reset threshold notifications so user can receive 70/98 after purchase
      notificationsSentThresholds: admin.firestore.FieldValue.delete(),
    };

    t.update(userRef, updates);
    return { skipped: false, totalRemaining: totalRemainingMB, plans: mergedPlans };
  });
}

// Migrate legacy fields into plans[] (idempotent) — updated to attach status and progress fields
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
        const expiry = userData.expiryDate || null;
        const status = expiry && new Date(expiry) < new Date() ? "expired" : (rem <= 0 ? "exhausted" : "active");
        migrationBuckets.push({
          name: userData.currentPlan || "Legacy Plan",
          dataLimitMB: Number(userData.planLimit || 0),
          remainingMB: Number(rem),
          purchasedAt: userData.lastPayment?.date || new Date().toISOString(),
          expiry,
          purchaseReference: userData.lastPayment?.reference || undefined,
          status,
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
        const status = expiry && new Date(expiry) < new Date() ? "expired" : "active";
        migrationBuckets.push({
          name: p.name || "Pending Plan",
          dataLimitMB: Number(p.dataLimit || 0),
          remainingMB: Number(p.dataLimit || 0),
          purchasedAt: p.purchasedAt || new Date().toISOString(),
          expiry,
          purchaseReference: p.reference || p.purchaseReference || undefined,
          status,
        });
      }
    }

    if (migrationBuckets.length > 0) {
      const mergedPlans = [...existingPlans, ...migrationBuckets];
      const { totalAllocatedMB, totalRemainingMB, totalUsedMB, progressPercent } = computeProgressFields(mergedPlans);
      const earliestExpiry = mergedPlans.length
        ? mergedPlans
            .map((p) => (p.expiry ? new Date(p.expiry) : null))
            .filter(Boolean)
            .sort((a, b) => a - b)[0]
        : null;

      // update user doc: set plans[], totalDataDisplay, clear legacy fields to avoid repeated migrations
      await userRef.update({
        plans: mergedPlans,
        totalDataDisplay: totalRemainingMB,
        planLimit: totalRemainingMB,
        totalAllocatedMB,
        totalRemainingMB,
        totalUsedMB,
        progressPercent,
        expiryDate: earliestExpiry ? earliestExpiry.toISOString() : admin.firestore.FieldValue.delete(),
        pendingPlan: admin.firestore.FieldValue.delete(),
        currentPlan: admin.firestore.FieldValue.delete(),
        dataUsed: admin.firestore.FieldValue.delete(),
        updatedAt: new Date().toISOString(),
        // reset threshold notifications so migration doesn't block alerts
        notificationsSentThresholds: admin.firestore.FieldValue.delete(),
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

// assign node: mark status=in_use, assignedTo:userEmail (or uid), increment load slightly
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

/**
 * backendActivateBridgeForUser(userIdentifier, nodeDocRef)
 * - Attempts to enable the tailscale device via API
 * - Updates the user document with vpnDeviceId/vpnAssignedNodeId/vpnBridgeActive
 * - Writes lastBridgeActivatedAt on node doc
 *
 * userIdentifier: either email (contains '@') or uid (doc id)
 * nodeDocRef: DocumentReference for tailscale_nodes doc
 */
async function backendActivateBridgeForUser(userIdentifier, nodeDocRef) {
  try {
    if (!nodeDocRef) {
      console.warn("backendActivateBridgeForUser: missing nodeDocRef");
      return { ok: false, reason: "missing_node_ref" };
    }

    // Ensure node exists
    const nodeSnap = await nodeDocRef.get();
    if (!nodeSnap.exists) {
      console.warn("backendActivateBridgeForUser: node doc missing");
      return { ok: false, reason: "node_missing" };
    }
    const nodeData = nodeSnap.data() || {};
    const deviceId = nodeDocRef.id;

    // Try to enable the device on Tailscale (best-effort)
    let enableRes = { ok: false };
    try {
      enableRes = await tailscaleEnableDevice(deviceId);
      if (!enableRes.ok) {
        console.warn(`backendActivateBridgeForUser: tailscaleEnableDevice returned not ok for device ${deviceId}`, enableRes.error || "");
      } else {
        console.log(`backendActivateBridgeForUser: tailscale device ${deviceId} enabled via API`);
      }
    } catch (e) {
      console.warn("backendActivateBridgeForUser: tailscaleEnableDevice exception:", e.message || e);
    }

    // find userRef (prefer email if identifier contains '@', else try doc id)
    let userRef = null;
    if (typeof userIdentifier === "string" && userIdentifier.includes("@")) {
      const q = await db.collection("users").where("email", "==", userIdentifier).limit(1).get();
      if (!q.empty) userRef = q.docs[0].ref;
    } else if (typeof userIdentifier === "string" && userIdentifier.length > 0) {
      const doc = await db.collection("users").doc(userIdentifier).get();
      if (doc.exists) userRef = doc.ref;
    }

    if (!userRef) {
      console.warn("backendActivateBridgeForUser: user not found for identifier", userIdentifier);
      return { ok: false, reason: "user_not_found" };
    }

    // Update user doc with bridge info (best-effort)
    try {
      await userRef.update({
        vpnDeviceId: deviceId,
        vpnAssignedNodeId: deviceId,
        vpnBridgeActive: true,
        vpnBridgeActivatedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    } catch (e) {
      console.warn("backendActivateBridgeForUser: failed to update user doc:", e.message || e);
    }

    // Note last activation on node doc
    try {
      await nodeDocRef.update({
        lastBridgeActivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (e) {
      console.warn("backendActivateBridgeForUser: failed to update node doc:", e.message || e);
    }

    return { ok: true, enabled: !!enableRes.ok };
  } catch (e) {
    console.warn("backendActivateBridgeForUser error:", e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ----------------------------
// PAYSTACK WEBHOOK (UPDATED: idempotent + migration into plans[] + normalize before append)
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

      // --- NORMALIZE statuses BEFORE appending new purchase
      try {
        await normalizeBucketStatuses(userRef);
      } catch (e) {
        console.warn("normalize before append failed (non-fatal):", e.message || e);
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

/**
 * Admin one-off endpoint: normalize & migrate all users
 * - runs migrateLegacyToPlansIfNeeded + normalizeBucketStatuses for each user
 * - use once (or occasionally) to update old accounts
 */
app.post("/admin/fix-all-plans", requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection("users").get();
    let processed = 0, migrated = 0, normalized = 0, errors = 0;
    for (const doc of snap.docs) {
      const ref = doc.ref;
      const data = doc.data() || {};
      try {
        const mig = await migrateLegacyToPlansIfNeeded(ref, data);
        if (mig && mig.migrated) migrated++;
        const norm = await normalizeBucketStatuses(ref);
        if (norm && norm.updated) normalized++;
        processed++;
      } catch (e) {
        console.warn(`admin/fix-all-plans error for ${doc.id}:`, e.message || e);
        errors++;
      }
    }
    res.json({ success: true, processed, migrated, normalized, errors });
  } catch (err) {
    console.error("/admin/fix-all-plans error:", err.message || err);
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

        // Activate backend-managed Bridge for user (best-effort)
        try {
          await backendActivateBridgeForUser(userIdentifier, docRef);
        } catch (e) {
          console.warn("auto-assign: backendActivateBridgeForUser failed:", e.message || e);
        }

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

    // Activate backend-managed Bridge for user (best-effort)
    try {
      await backendActivateBridgeForUser(userIdentifier, docRef);
    } catch (e) {
      console.warn("auto-assign: backendActivateBridgeForUser failed:", e.message || e);
    }

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
// Existing VPN session handlers (connect/disconnect/update-usage) - updated to use bucket consumption
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

            // Activate backend-managed Bridge for user (best-effort)
            try {
              await backendActivateBridgeForUser(uidOrEmail, pick.ref);
            } catch (e) {
              console.warn("connect: backendActivateBridgeForUser failed:", e.message || e);
            }
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

/**
 * Disconnect endpoint: consume data_used_mb from active buckets first, then update vpnActive flag.
 */
app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, data_used_mb = 0 } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const doc = snap.docs[0];
    const uRef = doc.ref;

    // Normalize statuses first so planLimit reflects active buckets
    try {
      await normalizeBucketStatuses(uRef);
    } catch (e) {
      console.warn("disconnect: normalize failed (non-fatal):", e.message || e);
    }

    // Consume usage from buckets transactionally
    let consumeRes = { consumed: 0, stillNeeded: data_used_mb, totalRemaining: 0, remainingActiveBuckets: 0 };
    try {
      consumeRes = await consumeUsageFromBuckets(uRef, Number(data_used_mb || 0));
    } catch (e) {
      console.warn("disconnect: consumeUsageFromBuckets failed (non-fatal):", e.message || e);
    }

    // After consumption, get updated user document to determine vpnActive/expiry
    const after = await uRef.get();
    const u = after.exists ? after.data() : {};

    // Compute percent (use progressPercent if present)
    const used = Number(u.totalUsedMB || (u.totalAllocatedMB - (u.totalRemainingMB || 0)) || u.dataUsed || 0);
    const totalAllocated = Number(u.totalAllocatedMB || 0);
    const percent = totalAllocated > 0 ? (used / totalAllocated) * 100 : 100;

    // Send threshold notifications (70%, 98%)
    try {
      await sendThresholdNotifications(uRef, u.email || username, percent);
    } catch (e) {
      console.warn("disconnect: sendThresholdNotifications failed:", e.message || e);
    }

    const over = (u.planLimit || 0) <= 0;
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();

    // Ensure vpnActive respects status
    await uRef.update({
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

    res.json({ success: true, consumed: consumeRes.consumed, remainingActiveBuckets: consumeRes.remainingActiveBuckets, totalRemaining: consumeRes.totalRemaining, totalAllocatedMB: consumeRes.totalAllocatedMB, totalUsedMB: consumeRes.totalUsedMB, progressPercent: consumeRes.progressPercent });
  } catch (err) {
    console.error("Disconnect error:", err.message || err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * update-usage endpoint: consume usage, send near-limit / exhausted notifications
 */
app.post("/vpn/session/update-usage", async (req, res) => {
  try {
    const { username, usage_mb = 0 } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const doc = snap.docs[0];
    const uRef = doc.ref;

    // Normalize statuses first so planLimit reflects active buckets
    try {
      await normalizeBucketStatuses(uRef);
    } catch (e) {
      console.warn("update-usage: normalize failed (non-fatal):", e.message || e);
    }

    // Consume usage transactionally
    const consumeRes = await consumeUsageFromBuckets(uRef, Number(usage_mb || 0));

    // Re-fetch user after consumption to compute percent
    const after = await uRef.get();
    const u = after.exists ? after.data() : {};
    const used = Number(u.totalUsedMB || (u.totalAllocatedMB - (u.totalRemainingMB || 0)) || u.dataUsed || 0);
    const totalAllocated = Number(u.totalAllocatedMB || 0);
    const percent = totalAllocated > 0 ? (used / totalAllocated) * 100 : 100;

    // send threshold notifications (70%, 98%, recorded)
    try {
      await sendThresholdNotifications(uRef, u.email || username, percent);
    } catch (e) {
      console.warn("update-usage: sendThresholdNotifications failed:", e.message || e);
    }

    if (percent >= 90 && percent < 100) {
      await sendUserNotification(
        username,
        "plan_near_limit",
        `⚠️ You've used ${percent.toFixed(0)}% of your active plan(s).`
      );
    }

    const over = (u.planLimit || 0) <= 0;
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();

    // Ensure vpnActive flag correct
    await uRef.update({
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

    res.json({ success: true, consumed: consumeRes.consumed, stillNeeded: consumeRes.stillNeeded, totalRemaining: consumeRes.totalRemaining, totalAllocatedMB: consumeRes.totalAllocatedMB, totalUsedMB: consumeRes.totalUsedMB, progressPercent: consumeRes.progressPercent });
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

      // Normalize buckets for each user (mark expired/exhausted and update totals)
      try {
        const pr = await normalizeBucketStatuses(userRef);
        // if normalization left zero active plans, increment disabled and ensure VPN disabled
        if (pr.remainingCount === 0) {
          disabled++;
        }
      } catch (e) {
        console.warn(`cron normalize error for ${doc.id}:`, e.message || e);
      }
    }

    res.status(200).send(`✅ Normalized plans for ${snap.size} users; ${disabled} users disabled (no active plans)`);
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
