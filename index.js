// index.js — SureData Backend (Production-ready)
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import crypto from "crypto";

dotenv.config();

const app = express();

// parse JSON for normal routes
app.use(express.json());
// CORS
app.use(cors());

// ---- Initialize Firebase ----
if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
  console.error("Missing Firebase env vars. Make sure FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY are set.");
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

// --- Helper: find user by identifier (username | email | phone)
async function findUserDocByIdentifier(identifier) {
  if (!identifier) return null;
  const users = db.collection("users");

  // try username
  let snap = await users.where("username", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  // if it looks like an email
  if (identifier.includes("@")) {
    snap = await users.where("email", "==", identifier.toLowerCase()).limit(1).get();
    if (!snap.empty) return snap.docs[0];
  }

  // finally try phone
  snap = await users.where("phone", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  return null;
}

// ---- Health and admin endpoints ----
app.get("/health", (req, res) => res.status(200).send("OK"));

app.get("/admin/summary", async (req, res) => {
  try {
    const usersSnap = await db.collection("users").get();
    const now = new Date();
    let total = usersSnap.size, active = 0, expired = 0, withPlan = 0;
    usersSnap.forEach(doc => {
      const u = doc.data();
      if (u.vpnActive) active++;
      if (u.expiryDate && new Date(u.expiryDate) < now) expired++;
      if (u.currentPlan) withPlan++;
    });
    res.json({ total, active, expired, withPlan });
  } catch (err) {
    console.error("admin/summary error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---- PAYSTACK WEBHOOK ----
// Use raw body to compute HMAC correctly.
app.post("/payments/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    if (!secret) {
      console.error("Missing PAYSTACK_SECRET_KEY");
      return res.status(500).send("Missing Paystack secret");
    }

    const receivedSig = req.headers["x-paystack-signature"] || "";
    const computed = crypto.createHmac("sha512", secret).update(req.body).digest("hex");
    if (computed !== receivedSig) {
      console.warn("Invalid Paystack signature");
      return res.status(400).send("Invalid signature");
    }

    const event = JSON.parse(req.body.toString());
    const ev = event.event;
    const data = event.data;

    if (ev === "charge.success") {
      const email = data.customer?.email?.toLowerCase?.() || null;
      const phone = data.customer?.phone || null;
      const amount = (data.amount || 0) / 100; // kobo -> naira
      const reference = data.reference;

      console.log(`💰 Paystack: charge.success from ${email || phone} amount ₦${amount}`);

      // log transaction (always)
      await db.collection("transactions").doc(reference).set({
        email: email || null,
        phone: phone || null,
        reference,
        amount,
        status: "success",
        raw: data,
        timestamp: new Date().toISOString(),
      });

      // find user
      let userDoc = null;
      if (email) userDoc = await findUserDocByIdentifier(email);
      if (!userDoc && phone) userDoc = await findUserDocByIdentifier(phone);

      if (!userDoc) {
        console.warn("Payment received but no user found:", email || phone);
        return res.status(200).send("Transaction recorded (no user)");
      }

      // plan mapping in naira -> MB, days
      const plans = {
        500: { name: "N500", dataLimitMB: 1024, days: 30 },    // 1 GB
        1000: { name: "N1000", dataLimitMB: 3072, days: 30 },  // 3 GB
        2000: { name: "N2000", dataLimitMB: 8192, days: 30 },  // 8 GB
        5000: { name: "N5000", dataLimitMB: 20480, days: 30 }, // 20 GB
      };

      const plan = plans[amount] || null;
      const userRef = userDoc.ref;

      await db.runTransaction(async (t) => {
        const snap = await t.get(userRef);
        if (!snap.exists) throw new Error("User disappeared during tx");
        const u = snap.data();
        const now = new Date();
        const oldExpiry = u.expiryDate ? new Date(u.expiryDate) : null;

        let expiryDate;
        if (plan) {
          expiryDate = oldExpiry && oldExpiry > now
            ? new Date(oldExpiry.getTime() + plan.days * 86400000)
            : new Date(now.getTime() + plan.days * 86400000);
        }

        const updates = {
          balance: (u.balance || 0) + amount,
          lastPayment: { reference, amount, date: now.toISOString() },
          updatedAt: now.toISOString(),
        };

        if (plan) {
          updates.currentPlan = plan.name;
          updates.planLimit = (u.planLimit || 0) + plan.dataLimitMB;
          updates.dataUsed = 0;
          updates.expiryDate = expiryDate.toISOString();
          updates.vpnActive = true;
        }

        t.update(userRef, updates);
      });

      console.log(`✅ Applied payment for user, plan: ${plan?.name || "balance-only"}`);
      return res.status(200).send("OK");
    }

    res.status(200).send("Ignored event");
  } catch (err) {
    console.error("Webhook processing error:", err);
    res.status(500).send("Server error");
  }
});

// ---- VPN SESSION CONNECT ----
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    if (!username) return res.status(400).send("Missing username");

    const userDoc = await findUserDocByIdentifier(username);
    if (!userDoc) return res.status(404).send("User not found");

    await userDoc.ref.update({
      vpnActive: true,
      lastConnectedIP: vpn_ip || null,
      lastConnectedAt: new Date().toISOString(),
    });

    console.log(`🟢 Connected: ${username} (${vpn_ip || "no ip"})`);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error("Connect error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---- VPN SESSION DISCONNECT ----
app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, bytes_sent = 0, bytes_received = 0, dataUsedMB } = req.body;
    if (!username) return res.status(400).send("Missing username");

    const userDoc = await findUserDocByIdentifier(username);
    if (!userDoc) return res.status(404).send("User not found");

    const uSnap = await userDoc.ref.get();
    const u = uSnap.data();

    // prefer explicit dataUsedMB if provided
    let usedMB = typeof dataUsedMB === "number" ? dataUsedMB : (Number(bytes_sent || 0) + Number(bytes_received || 0)) / (1024 * 1024);
    usedMB = Number(usedMB || 0);

    const newDataUsed = (u.dataUsed || 0) + usedMB;
    const planLimit = u.planLimit || 0;
    const expired = u.expiryDate && new Date(u.expiryDate) < new Date();
    const exhausted = planLimit > 0 && newDataUsed >= planLimit;
    const stillActive = !expired && !exhausted;

    await userDoc.ref.update({
      dataUsed: newDataUsed,
      vpnActive: stillActive,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    console.log(`📡 Disconnected: ${username} used ${usedMB.toFixed(2)}MB (total ${newDataUsed.toFixed(2)}MB). Active: ${stillActive}`);
    res.status(200).json({ success: true, dataUsedMB: usedMB, totalDataUsedMB: newDataUsed });
  } catch (err) {
    console.error("Disconnect error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---- AUTO EXPIRE CHECK (POST or GET accepted) ----
app.all("/cron/expire-check", async (req, res) => {
  try {
    console.log("⏰ Running expire-check...");
    const now = new Date();
    const usersSnap = await db.collection("users").get();
    let count = 0;

    for (const doc of usersSnap.docs) {
      const u = doc.data();
      const expired = u.expiryDate && new Date(u.expiryDate) < now;
      const exhausted = (u.planLimit || 0) > 0 && (u.dataUsed || 0) >= u.planLimit;

      if (expired || exhausted) {
        await doc.ref.update({ vpnActive: false });
        console.log(`🔴 Disabled ${u.username || u.email}: expired=${expired}, exhausted=${exhausted}`);
        count++;
      }
    }

    res.status(200).send(`OK — processed ${usersSnap.size} users, disabled ${count}`);
  } catch (err) {
    console.error("Expiry check error:", err);
    res.status(500).send("Cron error");
  }
});

// ---- Utility: attempt to disable a Tailscale device (best-effort) ----
async function attemptDisableTailscaleDevice(nodeId) {
  const token = process.env.TAILSCALE_API_KEY;
  const tailnet = process.env.TAILSCALE_TAILNET;
  if (!token || !tailnet) throw new Error("Missing TAILSCALE_API_KEY or TAILSCALE_TAILNET");

  const API_BASE = `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnet)}`;

  // best-effort paths — try variants and catch errors
  const tryPaths = [
    `${API_BASE}/devices/${encodeURIComponent(nodeId)}/disable`, // plausible
    `${API_BASE}/devices/${encodeURIComponent(nodeId)}:disable`, // alternate colon style
    `${API_BASE}/devices/${encodeURIComponent(nodeId)}`, // PUT with body {disabled: true} (if supported)
  ];

  for (const path of tryPaths) {
    try {
      // If path ends with '/disable' or ':disable' we POST, otherwise try PATCH
      if (path.endsWith("/disable") || path.includes(":disable")) {
        const r = await fetch(path, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
        if (r.ok) return { ok: true, path };
        const text = await r.text();
        console.warn(`Tailscale disable failed (path ${path}): ${r.status} ${text}`);
      } else {
        // try PATCH to set disabled flag (best-effort)
        const r = await fetch(path, {
          method: "PATCH",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ disabled: true }),
        });
        if (r.ok) return { ok: true, path };
        const text = await r.text();
        console.warn(`Tailscale disable (PATCH) failed (path ${path}): ${r.status} ${text}`);
      }
    } catch (err) {
      console.warn("Tailscale attempt error for path", path, err.message);
    }
  }
  return { ok: false };
}

// ---- FULL TAILSCALE SYNC (uses Tailscale API to disable devices) ----
app.all("/cron/tailscale-sync", async (req, res) => {
  try {
    console.log("🔄 Running full Tailscale sync...");

    const token = process.env.TAILSCALE_API_KEY;
    const tailnet = process.env.TAILSCALE_TAILNET;
    if (!token || !tailnet) {
      console.warn("Tailscale not configured — skipping API disable step");
    }

    // Step A: scan Firestore, determine who should be active
    const usersSnap = await db.collection("users").get();
    const now = new Date();
    const activeUsers = [];
    const toDisableUsers = [];

    for (const doc of usersSnap.docs) {
      const u = doc.data();
      const expiry = u.expiryDate ? new Date(u.expiryDate) : null;
      const expired = expiry && expiry < now;
      const planLimit = u.planLimit || 0;
      const dataUsed = u.dataUsed || 0;
      const exhausted = planLimit > 0 && dataUsed >= planLimit;
      const shouldBeActive = !expired && !exhausted && !!u.currentPlan;

      // auto-fix Firestore flag if mismatch
      if ((u.vpnActive || false) !== shouldBeActive) {
        await doc.ref.update({ vpnActive: shouldBeActive, updatedAt: new Date().toISOString() });
        console.log(`${shouldBeActive ? "Re-enabled" : "Disabled"} ${u.username || u.email || doc.id}`);
      }

      if (shouldBeActive) {
        activeUsers.push({ uid: doc.id, username: u.username || u.email || u.phone, plan: u.currentPlan, expiry: u.expiryDate, dataUsed: dataUsed, planLimit });
      } else if (u.vpnActive) {
        // currently marked active but should not be
        toDisableUsers.push({ uid: doc.id, username: u.username || u.email || u.phone, reason: expired ? "expired" : "data exhausted" });
      }
    }

    // Step B: if Tailscale API is configured, fetch devices and attempt disabling
    const actions = [];
    if (token && tailnet) {
      const API_BASE = `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnet)}`;
      const devicesUrl = `${API_BASE}/devices`;
      try {
        const resp = await fetch(devicesUrl, { headers: { Authorization: `Bearer ${token}` } });
        if (!resp.ok) {
          const t = await resp.text();
          console.warn("Tailscale devices fetch failed:", resp.status, t);
        } else {
          const devicesJson = await resp.json();
          const devices = devicesJson.devices || [];

          // For each to-disable user try to find matching device(s) and disable
          for (const u of toDisableUsers) {
            // try to match by username/email/hostname or user field
            const matches = devices.filter(d => {
              const host = (d.hostname || "").toLowerCase();
              const nodeUsers = (d.users || []).map(x => String(x).toLowerCase()).join(" ");
              const username = String(u.username || "").toLowerCase();
              return host.includes(username) || nodeUsers.includes(username) || (d.user && String(d.user).toLowerCase().includes(username));
            });

            if (matches.length === 0) {
              actions.push({ username: u.username, action: "no-device-found" });
              continue;
            }

            for (const m of matches) {
              const nodeId = m.id || m.nodeId || m.deviceId || m.id;
              if (!nodeId) {
                actions.push({ username: u.username, device: m, action: "no-nodeId" });
                continue;
              }

              const r = await attemptDisableTailscaleDevice(nodeId);
              actions.push({ username: u.username, nodeId, disabled: r.ok, path: r.path || null });
            }
          }
        }
      } catch (err) {
        console.error("Tailscale API error:", err);
      }
    } else {
      // Not configured; just report
      console.log("Tailscale API not configured; no device-level changes performed.");
    }

    // Build usage summary (plan progress)
    const syncedSummary = activeUsers.map(u => ({
      uid: u.uid,
      username: u.username,
      plan: u.plan,
      expiry: u.expiry,
      usagePct: u.planLimit ? ((u.dataUsed / u.planLimit) * 100).toFixed(1) + "%" : "N/A",
      usedMB: u.dataUsed,
      planLimitMB: u.planLimit,
    }));

    console.log(`Sync result — active: ${activeUsers.length}, toDisable: ${toDisableUsers.length}, actions: ${actions.length}`);
    return res.status(200).json({
      message: "Tailscale sync completed",
      activeCount: activeUsers.length,
      toDisableCount: toDisableUsers.length,
      syncedSummary,
      actions,
    });
  } catch (err) {
    console.error("Tailscale sync error:", err);
    res.status(500).send(`Tailscale sync failed: ${err.message}`);
  }
});

// ---- Start server ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 SureData backend running on port ${PORT}`);
});
