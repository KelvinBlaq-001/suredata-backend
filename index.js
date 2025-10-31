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
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
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

      // Allow easy testing
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

      // Match plan by amount
      const plans = {
        500: { name: "Basic Plan", dataLimit: 2 * 1024, days: 30 },
        1000: { name: "Standard Plan", dataLimit: 4 * 1024, days: 30 },
        2000: { name: "Pro Plan", dataLimit: 8 * 1024, days: 30 },
        5000: { name: "Ultra Plan", dataLimit: 20 * 1024, days: 30 },
      };
      const plan = plans[amount];
      if (!plan) return res.sendStatus(200);

      // Find user
      const usersRef = db.collection("users");
      const snap = await usersRef.where("email", "==", email).limit(1).get();
      if (snap.empty) {
        console.log(`❌ User not found for email ${email}`);
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
      const userData = snap.docs[0].data();

      const now = new Date();
      const currentExpiry = userData.expiryDate
        ? new Date(userData.expiryDate)
        : null;
      const isActive = currentExpiry && currentExpiry > now;

      const newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + plan.days);

      const remainingData = Math.max(
        (userData.planLimit || 0) - (userData.dataUsed || 0),
        0
      );

      let totalLimit = plan.dataLimit;
      if (isActive && remainingData > 0) {
        totalLimit += remainingData;
        console.log(
          `🔄 Rollover applied for ${email}: ${remainingData}MB leftover + ${plan.dataLimit}MB new`
        );
      }

      await userRef.update({
        currentPlan: plan.name,
        planLimit: totalLimit,
        dataUsed: isActive ? userData.dataUsed || 0 : 0,
        expiryDate: newExpiry.toISOString(),
        vpnActive: true,
        lastPayment: {
          amount,
          reference,
          date: now.toISOString(),
        },
        updatedAt: now.toISOString(),
      });

      console.log(
        `✅ ${email} purchased ${plan.name} — total ${totalLimit}MB (after rollover if any)`
      );

      // Firestore notification
      await sendUserNotification(
        email,
        "plan_purchased",
        `🎉 You’ve successfully purchased the ${plan.name}. Total: ${totalLimit}MB.`
      );

      res.sendStatus(200);
    } catch (err) {
      console.error("❌ Webhook error:", err);
      res.sendStatus(500);
    }
  }
);

// --- Enable JSON parsing + add request logger ---
app.use(express.json());
app.use(cors());
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
// NEW: Tailscale Node Setup
// ----------------------
app.post("/admin/setup-tailscale-nodes", async (_, res) => {
  try {
    const tailscaleRef = db.collection("tailscale_nodes");
    const snap = await tailscaleRef.limit(1).get();

    if (!snap.empty) {
      return res.status(200).json({
        message: "✅ tailscale_nodes already exists. No new nodes added.",
      });
    }

    const defaultNodes = [
      {
        deviceId: "abc123",
        hostname: "suredata-node-1",
        ip: "100.64.0.5",
        user: "admin@suredata.com",
        assignedTo: null,
        status: "free",
      },
      {
        deviceId: "def456",
        hostname: "suredata-node-2",
        ip: "100.64.0.6",
        user: "admin@suredata.com",
        assignedTo: null,
        status: "free",
      },
      {
        deviceId: "ghi789",
        hostname: "suredata-node-3",
        ip: "100.64.0.7",
        user: "admin@suredata.com",
        assignedTo: null,
        status: "free",
      },
    ];

    const batch = db.batch();
    for (const node of defaultNodes) {
      const docRef = tailscaleRef.doc();
      batch.set(docRef, node);
    }
    await batch.commit();

    res.status(200).json({
      message: "✅ tailscale_nodes collection created with default nodes",
      nodes: defaultNodes,
    });
  } catch (err) {
    console.error("setup-tailscale-nodes error:", err.message);
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

// (the rest of your VPN, CRON, and notify/test endpoints remain unchanged)
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

// --- Start Server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 SureData backend running on port ${PORT}`));
