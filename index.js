// index.js — SureData Backend (Production-ready, Rollover + Auto-Disconnect + Tailscale hooks)
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import crypto from "crypto";
import fetch from "node-fetch"; // ensure node-fetch is installed

dotenv.config();

const app = express();

// --- Note: keep express.raw for the webhook route only. Use json for all others.
// We'll attach express.json() after the webhook route (see below).

// ---- Initialize Firebase ----
if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY
) {
  console.error(
    "Missing Firebase env vars. Make sure FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY are set."
  );
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

// --------------------------
// Helper: Disable VPN Access (global, reusable)
// --------------------------
async function disableVPNAccess(username) {
  try {
    const vpnAPI = process.env.VPN_DISABLE_ENDPOINT; // e.g. "http://127.0.0.1:8081/vpn/disable"
    if (!vpnAPI) {
      console.warn("⚠️ No VPN_DISABLE_ENDPOINT set in env - skipping actual disable call");
      return { ok: false, reason: "no_endpoint" };
    }

    const r = await fetch(vpnAPI, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });

    if (!r.ok) {
      const text = await r.text();
      console.warn(`⚠️ Failed to disable VPN for ${username} (${r.status}) - ${text}`);
      return { ok: false, status: r.status, text };
    }

    console.log(`🛑 VPN access disabled for ${username}`);
    return { ok: true };
  } catch (err) {
    console.error("❌ disableVPNAccess error:", err.message);
    return { ok: false, error: err.message };
  }
}

// ---------------------------- 
// PAYSTACK WEBHOOK (with rollover logic)
// ----------------------------
// Use express.raw for this route ONLY so we can verify signature with the raw bytes
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;
      if (!secret) {
        console.error("Missing PAYSTACK_SECRET_KEY in env");
        return res.status(500).send("Server misconfigured");
      }

      const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body));
      const computedHash = crypto.createHmac("sha512", secret).update(rawBody).digest("hex");
      const receivedHash = req.headers["x-paystack-signature"];

      // Optionally support a test bypass in non-production (helpful for manual tests)
      if (process.env.NODE_ENV !== "production" && receivedHash === "test-bypass") {
        console.log("🧪 Paystack signature bypass (test mode)");
      } else if (computedHash !== receivedHash) {
        console.warn("⚠️ Invalid Paystack signature");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      console.log("📩 Paystack event:", event.event);

      if (event.event === "charge.success") {
        const data = event.data;
        const reference = data.reference;
        const amount = data.amount / 100; // Paystack sends kobo
        const email = (data.customer?.email || "").toLowerCase();

        console.log(`💰 Payment from ${email}: ₦${amount}`);

        // Firestore: find user
        const usersRef = db.collection("users");
        const snapshot = await usersRef.where("email", "==", email).limit(1).get();

        if (snapshot.empty) {
          console.warn("⚠️ No user found for:", email);
          // still record transaction
          await db.collection("transactions").doc(reference).set({
            email,
            reference,
            amount,
            status: "success",
            timestamp: new Date().toISOString(),
            note: "user_not_found",
          });
          return res.sendStatus(200);
        }

        const userDoc = snapshot.docs[0];
        const userRef = userDoc.ref;

        // plan map (NGN -> MB and days)
        const plans = {
          500: { name: "N500", dataLimit: 1 * 1024, days: 30 }, // 1GB => 1024 MB
          1000: { name: "N1000", dataLimit: 3 * 1024, days: 30 }, // 3GB
          2000: { name: "N2000", dataLimit: 8 * 1024, days: 30 }, // 8GB
          5000: { name: "N5000", dataLimit: 20 * 1024, days: 30 }, // 20GB
        };

        const plan = plans[amount];
        if (!plan) {
          console.warn(`⚠️ Unknown plan amount: ₦${amount}`);
          // still record transaction but ignore plan application
          await db.collection("transactions").doc(reference).set({
            uid: userRef.id,
            email,
            reference,
            amount,
            status: "success",
            plan: null,
            timestamp: new Date().toISOString(),
          });
          return res.sendStatus(200);
        }

        // transaction: compute rollover/stacking safely
        await db.runTransaction(async (t) => {
          const snap = await t.get(userRef);
          if (!snap.exists) throw new Error("User not found during transaction");
          const u = snap.data();

          const now = new Date();
          const currentDataUsed = u.dataUsed || 0;
          const currentPlanLimit = u.planLimit || 0;
          const currentExpiry = u.expiryDate ? new Date(u.expiryDate) : null;
          const isPlanActive = currentExpiry && currentExpiry > now;

          // new expiry (from now)
          const newExpiry = new Date();
          newExpiry.setDate(newExpiry.getDate() + plan.days);

          let finalPlanLimit;
          let finalExpiry;

          if (isPlanActive) {
            const remainingData = Math.max(currentPlanLimit - currentDataUsed, 0);
            finalPlanLimit = remainingData + plan.dataLimit;
            // choose the later expiry (keeps longest valid window)
            finalExpiry = newExpiry > currentExpiry ? newExpiry : currentExpiry;
            console.log(`🔄 Rollover applied for ${email}: ${remainingData}MB + ${plan.dataLimit}MB`);
          } else {
            finalPlanLimit = plan.dataLimit;
            finalExpiry = newExpiry;
            console.log(`🆕 New plan started for ${email}: ${plan.dataLimit}MB`);
          }

          const updates = {
            balance: (u.balance || 0) + amount,
            currentPlan: plan.name,
            planLimit: finalPlanLimit,
            dataUsed: 0,
            expiryDate: finalExpiry.toISOString(),
            vpnActive: true,
            lastPayment: { reference, amount, date: now.toISOString() },
            updatedAt: now.toISOString(),
          };

          t.update(userRef, updates);

          const txRef = db.collection("transactions").doc(reference);
          t.set(txRef, {
            uid: userRef.id,
            email,
            reference,
            amount,
            status: "success",
            plan: plan.name,
            dataAdded: plan.dataLimit,
            totalLimit: finalPlanLimit,
            timestamp: new Date().toISOString(),
          });
        });

        console.log(`✅ ${email} purchased ${plan.name} (${plan.dataLimit}MB)`);
      }

      return res.sendStatus(200);
    } catch (err) {
      console.error("❌ Webhook error:", err && err.message ? err.message : err);
      return res.sendStatus(500);
    }
  }
);

// Re-enable JSON parsing for all other routes
app.use(express.json());
app.use(cors());

// ---- Helper: find user by identifier (username | email | phone)
async function findUserDocByIdentifier(identifier) {
  if (!identifier) return null;
  const users = db.collection("users");

  let snap = await users.where("username", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  if (identifier.includes("@")) {
    snap = await users.where("email", "==", identifier.toLowerCase()).limit(1).get();
    if (!snap.empty) return snap.docs[0];
  }

  snap = await users.where("phone", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  return null;
}

// ---- Health & admin endpoints ----
app.get("/health", (req, res) => res.status(200).send("OK"));

app.get("/admin/summary", async (req, res) => {
  try {
    const usersSnap = await db.collection("users").get();
    const now = new Date();
    let total = usersSnap.size,
      active = 0,
      expired = 0,
      withPlan = 0;
    usersSnap.forEach((doc) => {
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

// ---- VPN SESSION CONNECT ----
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    console.log("🟢 VPN Connect triggered for:", username, vpn_ip);

    const snapshot = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snapshot.empty) {
      console.log("⚠️ No user found for:", username);
      return res.status(404).json({ error: "User not found" });
    }

    const userDoc = snapshot.docs[0];
    await userDoc.ref.update({
      vpnActive: true,
      vpnIP: vpn_ip,
      lastConnect: new Date().toISOString(),
    });

    console.log(`✅ Updated user ${username} as connected`);
    res.json({ success: true });
  } catch (error) {
    console.error("❌ Connect error:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ---- VPN SESSION DISCONNECT ----
app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, vpn_ip, data_used_mb = 0 } = req.body;
    console.log("🔴 VPN Disconnect triggered for:", username, vpn_ip, "Data used:", data_used_mb, "MB");

    const snapshot = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snapshot.empty) return res.status(404).json({ error: "User not found" });

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    const updatedDataUsed = (user.dataUsed || 0) + data_used_mb;
    const overLimit = updatedDataUsed >= (user.planLimit || Infinity);
    const expired = user.expiryDate && new Date(user.expiryDate) < new Date();

    const updates = {
      dataUsed: updatedDataUsed,
      vpnActive: !overLimit && !expired,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await userDoc.ref.update(updates);
    console.log(`✅ Updated user ${username} as disconnected. Total used: ${updatedDataUsed}MB`);

    // Auto-disable in VPN provider (best-effort)
    if (overLimit || expired) {
      console.log(`⚠️ Auto-disabling VPN for ${username}`);
      await disableVPNAccess(username);
    }

    res.json({ success: true, username, dataUsed: updatedDataUsed, overLimit, expired });
  } catch (error) {
    console.error("❌ Disconnect error:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ---- VPN SESSION USAGE UPDATE ----
app.post("/vpn/session/update-usage", async (req, res) => {
  try {
    const { username, usage_mb = 0 } = req.body;
    console.log(`📊 Updating usage for ${username}: +${usage_mb}MB`);

    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const userDoc = snap.docs[0];
    const user = userDoc.data();

    const newDataUsed = (user.dataUsed || 0) + usage_mb;
    const overLimit = newDataUsed >= (user.planLimit || Infinity);
    const expired = user.expiryDate && new Date(user.expiryDate) < new Date();

    const updates = {
      dataUsed: newDataUsed,
      vpnActive: !overLimit && !expired,
      updatedAt: new Date().toISOString(),
    };

    await userDoc.ref.update(updates);
    console.log(`✅ Updated usage for ${username}. Total: ${newDataUsed}MB`);

    if (overLimit || expired) {
      console.log(`⚠️ Auto-disabling VPN for ${username}`);
      await disableVPNAccess(username);
    }

    res.json({ success: true, username, dataUsed: newDataUsed, overLimit, expired });
  } catch (err) {
    console.error("❌ Usage update error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- AUTO EXPIRE CHECK ----
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
        await doc.ref.update({ vpnActive: false, updatedAt: new Date().toISOString() });
        await disableVPNAccess(u.email || u.username || doc.id);
        count++;
      }
    }

    res.status(200).send(`✅ Processed ${usersSnap.size} users, disabled ${count}`);
  } catch (err) {
    console.error("Expiry check error:", err);
    res.status(500).send("Cron error");
  }
});

// ---- TAILSCALE SYNC ----
app.get("/cron/tailscale-sync", async (req, res) => {
  try {
    const tailnet = process.env.TAILSCALE_TAILNET;
    const apiKey = process.env.TAILSCALE_API_KEY;

    if (!tailnet || !apiKey) {
      console.warn("⚠️ Missing TAILSCALE_API_KEY or TAILSCALE_TAILNET");
      return res.status(500).send("Tailscale config missing");
    }

    console.log("🔄 Fetching Tailscale devices...");
    const response = await fetch(
      `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnet)}/devices`,
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
        },
      }
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Tailscale API error ${response.status}: ${text}`);
    }

    const data = await response.json();
    const devices = data.devices || [];
    console.log(`📡 Found ${devices.length} Tailscale devices`);

    const usersSnap = await db.collection("users").get();
    const now = new Date();
    let checked = 0,
      disabled = 0;

    for (const doc of usersSnap.docs) {
      const u = doc.data();
      const expired = u.expiryDate && new Date(u.expiryDate) < now;
      const exhausted =
        (u.planLimit || 0) > 0 && (u.dataUsed || 0) >= u.planLimit;

      if (expired || exhausted) {
        // Match device by user email or hostname
        const match = devices.find(
          (d) =>
            d.user?.toLowerCase().includes((u.email || "").toLowerCase()) ||
            d.hostname
              ?.toLowerCase()
              .includes((u.email || "").split("@")[0].toLowerCase())
        );

        if (match) {
          console.log(`🛑 Disabling device ${match.hostname} for ${u.email}`);
          await fetch(
            `https://api.tailscale.com/api/v2/device/${match.id}/disable`,
            {
              method: "POST",
              headers: { Authorization: `Bearer ${apiKey}` },
            }
          );
          disabled++;
        }

        await doc.ref.update({ vpnActive: false });
      }

      checked++;
    }

    const msg = `✅ Tailscale sync complete: ${checked} users checked, ${disabled} devices disabled`;
    console.log(msg);
    res.status(200).send(msg);
  } catch (err) {
    console.error("❌ Tailscale sync error:", err);
    res.status(500).send(err.message);
  }
});


// ---- Admin/manual endpoint: Trigger remote VPN disable (for testing) ----
app.post("/vpn/disable", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    const result = await disableVPNAccess(username);
    return res.json({ success: result.ok, result });
  } catch (err) {
    console.error("vpn/disable error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ---- Start server ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 SureData backend running on port ${PORT}`);
});
