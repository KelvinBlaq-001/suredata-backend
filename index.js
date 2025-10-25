// index.js — SureData Backend (Production-ready, Rollover + Auto-Disconnect + Tailscale hooks)
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

// --- Notification Helper (FCM-ready stub) ---
async function sendUserNotification(email, type, message) {
  try {
    console.log(`🔔 Notification [${type}] → ${email}: ${message}`);
    await db.collection("notifications").add({
      email,
      type,
      message,
      timestamp: new Date().toISOString(),
      read: false,
    });
  } catch (err) {
    console.error("Notification error:", err.message);
  }
}

// --- Helper: Disable VPN Access ---
async function disableVPNAccess(username) {
  try {
    const vpnAPI = process.env.VPN_DISABLE_ENDPOINT;
    if (!vpnAPI) {
      console.warn("⚠️ No VPN_DISABLE_ENDPOINT set — skipping actual disable call");
      return { ok: false, reason: "no_endpoint" };
    }

    const res = await fetch(vpnAPI, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });

    if (!res.ok) {
      const text = await res.text();
      console.warn(`⚠️ Failed to disable VPN for ${username}: ${text}`);
      return { ok: false, status: res.status, text };
    }

    console.log(`🛑 VPN access disabled for ${username}`);
    return { ok: true };
  } catch (err) {
    console.error("disableVPNAccess error:", err.message);
    return { ok: false, error: err.message };
  }
}

// ----------------------------
// PAYSTACK WEBHOOK (with rollover logic)
// ----------------------------
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;
      if (!secret) return res.status(500).send("Server misconfigured");

      const rawBody = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(JSON.stringify(req.body));

      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(rawBody)
        .digest("hex");

      const receivedHash = req.headers["x-paystack-signature"];

      if (
        process.env.NODE_ENV !== "production" &&
        receivedHash === "test-bypass"
      ) {
        console.log("🧪 Paystack test-bypass active");
      } else if (computedHash !== receivedHash) {
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      if (event.event !== "charge.success") return res.sendStatus(200);

      const data = event.data;
      const reference = data.reference;
      const amount = data.amount / 100;
      const email = (data.customer?.email || "").toLowerCase();

      const plans = {
        500: { name: "N500", dataLimit: 1 * 1024, days: 30 },
        1000: { name: "N1000", dataLimit: 3 * 1024, days: 30 },
        2000: { name: "N2000", dataLimit: 8 * 1024, days: 30 },
        5000: { name: "N5000", dataLimit: 20 * 1024, days: 30 },
      };

      const plan = plans[amount];
      if (!plan) return res.sendStatus(200);

      const usersRef = db.collection("users");
      const snap = await usersRef.where("email", "==", email).limit(1).get();
      if (snap.empty) {
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

      const userRef = snap.docs[0].ref;

      await db.runTransaction(async (t) => {
        const doc = await t.get(userRef);
        if (!doc.exists) throw new Error("User not found");
        const u = doc.data();

        const now = new Date();
        const currentDataUsed = u.dataUsed || 0;
        const currentPlanLimit = u.planLimit || 0;
        const currentExpiry = u.expiryDate ? new Date(u.expiryDate) : null;
        const isActive = currentExpiry && currentExpiry > now;

        const newExpiry = new Date();
        newExpiry.setDate(newExpiry.getDate() + plan.days);

        let finalPlanLimit = plan.dataLimit;
        let finalExpiry = newExpiry;

        // ✅ If user still has an active plan, roll over unused data
        if (isActive) {
          const remainingData = Math.max(currentPlanLimit - currentDataUsed, 0);
          finalPlanLimit += remainingData; // add leftover data to new plan
          finalExpiry =
            newExpiry > currentExpiry ? newExpiry : currentExpiry; // extend or keep
        }

        // ✅ Reset usage only if plan had expired, otherwise keep tracking usage
        const updates = {
          balance: (u.balance || 0) + amount,
          currentPlan: plan.name,
          planLimit: finalPlanLimit,
          dataUsed: isActive ? currentDataUsed : 0,
          expiryDate: finalExpiry.toISOString(),
          vpnActive: true,
          lastPayment: { reference, amount, date: now.toISOString() },
          updatedAt: now.toISOString(),
        };

        t.update(userRef, updates);
        t.set(db.collection("transactions").doc(reference), {
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

      await sendUserNotification(
        email,
        "plan_activated",
        `Your ${plan.name} plan (${plan.dataLimit / 1024}GB) has been activated.`
      );

      res.sendStatus(200);
    } catch (err) {
      console.error("Webhook error:", err.message);
      res.sendStatus(500);
    }
  }
);

// --- Enable JSON parsing + add request logger middleware ---
app.use(express.json());
app.use(cors());

// 🪵 Universal request logger — this is the new part
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
    console.error("admin/summary error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// VPN SESSION HANDLERS
// ----------------------
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    const snap = await db.collection("users").where("email", "==", username).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    await snap.docs[0].ref.update({
      vpnActive: true,
      vpnIP: vpn_ip,
      lastConnect: new Date().toISOString(),
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Connect error:", err.message);
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
    console.error("Disconnect error:", err.message);
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
    console.error("Usage update error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ----------------------
// CRON JOBS
// ----------------------
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
    console.error("Cron expire-check error:", err.message);
    res.status(500).send(err.message);
  }
});

app.get("/cron/tailscale-sync", async (_, res) => {
  try {
    const tailnet = process.env.TAILSCALE_TAILNET;
    const apiKey = process.env.TAILSCALE_API_KEY;

    if (!tailnet || !apiKey)
      return res.status(500).send("Missing Tailscale config");

    const response = await fetch(
      `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(
        tailnet
      )}/devices`,
      { headers: { Authorization: `Bearer ${apiKey}` } }
    );

    if (!response.ok) throw new Error(`Tailscale API error ${response.status}`);
    const data = await response.json();
    const devices = data.devices || [];

    const snap = await db.collection("users").get();
    const now = new Date();
    let disabled = 0;

    for (const doc of snap.docs) {
      const u = doc.data();
      const expired = u.expiryDate && new Date(u.expiryDate) < now;
      const exhausted =
        (u.planLimit || 0) > 0 && (u.dataUsed || 0) >= u.planLimit;

      if (expired || exhausted) {
        const match = devices.find((d) =>
          d.user?.toLowerCase().includes((u.email || "").toLowerCase())
        );
        if (match) {
          await fetch(
            `https://api.tailscale.com/api/v2/device/${match.id}/disable`,
            { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } }
          );
          disabled++;
        }
        await doc.ref.update({ vpnActive: false });
      }
    }

    res.status(200).send(`✅ Disabled ${disabled} devices`);
  } catch (err) {
    console.error("Tailscale sync error:", err.message);
    res.status(500).send(err.message);
  }
});

// ----------------------
// Misc. Test Endpoints
// ----------------------
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

    const result = await disableVPNAccess(username);
    res.json({ success: result.ok, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 SureData backend running on port ${PORT}`));
