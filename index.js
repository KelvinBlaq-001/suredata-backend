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
      timestamp: admin.firestore.FieldValue.serverTimestamp(), // Proper Firestore Timestamp
      read: false,
    });
  } catch (err) {
    console.error("Notification error:", err.message);
  }
}

// ----------------------
// TAILSCALE INTEGRATION
// ----------------------
// Requires:
//   TAILSCALE_API_KEY (api key from Tailscale: machine user or service key)
//   TAILSCALE_TAILNET (your tailnet name, e.g. example.tailscale.net or tailnet slug)

function _tailscaleAuthHeader() {
  const apiKey = process.env.TAILSCALE_API_KEY || "";
  // Tailscale expects Basic auth with the API key as username and empty password
  // "Authorization: Basic base64(apiKey + ':')"
  const token = Buffer.from(`${apiKey}:`).toString("base64");
  return `Basic ${token}`;
}

async function findTailscaleDevice(email) {
  try {
    const tailnet = process.env.TAILSCALE_TAILNET;
    if (!tailnet) throw new Error("TAILSCALE_TAILNET not set");
    const url = `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnet)}/devices`;
    const res = await fetch(url, {
      method: "GET",
      headers: { Authorization: _tailscaleAuthHeader() },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale devices fetch failed: ${res.status} ${text}`);
    }
    const json = await res.json();
    const devices = json.devices || [];
    const lower = (email || "").toLowerCase();
    // find device where device.user contains the email (case-insensitive)
    const match = devices.find((d) => {
      if (!d.user) return false;
      return d.user.toLowerCase().includes(lower);
    });
    return match || null;
  } catch (err) {
    console.warn("findTailscaleDevice error:", err.message);
    return null;
  }
}

async function enableTailscaleDevice(deviceId) {
  try {
    const tailnet = process.env.TAILSCALE_TAILNET;
    if (!tailnet) throw new Error("TAILSCALE_TAILNET not set");
    // endpoint used in your code was .../device/{id}/disable — mirror with enable
    const url = `https://api.tailscale.com/api/v2/device/${encodeURIComponent(deviceId)}/enable`;
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: _tailscaleAuthHeader() },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale enable failed: ${res.status} ${text}`);
    }
    return { ok: true };
  } catch (err) {
    console.warn("enableTailscaleDevice error:", err.message);
    return { ok: false, error: err.message };
  }
}

async function disableTailscaleDevice(deviceId) {
  try {
    const url = `https://api.tailscale.com/api/v2/device/${encodeURIComponent(deviceId)}/disable`;
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: _tailscaleAuthHeader() },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Tailscale disable failed: ${res.status} ${text}`);
    }
    return { ok: true };
  } catch (err) {
    console.warn("disableTailscaleDevice error:", err.message);
    return { ok: false, error: err.message };
  }
}

// High-level helpers used by your flows:
async function enableVPNAccess(username) {
  try {
    // username is email
    const device = await findTailscaleDevice(username);
    if (!device) {
      console.log(`No tailscale device found for ${username}`);
      return { ok: false, reason: "no_device" };
    }
    const did = device.id || device.idString || device.node_id || device.key;
    const res = await enableTailscaleDevice(did);
    if (res.ok) {
      console.log(`✅ Tailscale device ${did} enabled for ${username}`);
      return { ok: true, deviceId: did };
    } else {
      return { ok: false, error: res.error };
    }
  } catch (err) {
    console.error("enableVPNAccess error:", err.message);
    return { ok: false, error: err.message };
  }
}

async function disableVPNAccess(username) {
  try {
    const vpnAPI = process.env.VPN_DISABLE_ENDPOINT;
    // existing external VPN disable endpoint (optional)
    if (vpnAPI) {
      const res = await fetch(vpnAPI, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!res.ok) {
        const text = await res.text();
        console.warn(`⚠️ Failed to disable VPN for ${username} via vpnAPI: ${text}`);
      } else {
        console.log(`🛑 VPN access disabled via vpnAPI for ${username}`);
      }
    }

    // Also attempt to disable Tailscale device if present
    const device = await findTailscaleDevice(username);
    if (device) {
      const did = device.id || device.idString || device.node_id || device.key;
      const r = await disableTailscaleDevice(did);
      if (r.ok) {
        console.log(`🛑 Tailscale device ${did} disabled for ${username}`);
      } else {
        console.warn("Tailscale disable error:", r.error);
      }
    } else {
      console.log(`No Tailscale device found for ${username} to disable.`);
    }

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

      // ✅ Match plan by amount
      const plans = {
        500: { name: "Basic Plan", dataLimit: 2 * 1024, days: 30 },
        1000: { name: "Standard Plan", dataLimit: 4 * 1024, days: 30 },
        2000: { name: "Pro Plan", dataLimit: 8 * 1024, days: 30 },
        5000: { name: "Ultra Plan", dataLimit: 20 * 1024, days: 30 },
      };
      const plan = plans[amount];
      if (!plan) return res.sendStatus(200);

      // ✅ Find user
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

      // ✅ Compute rollover if applicable
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

      // 📨 Send notification to Firestore
      await sendUserNotification(
        email,
        "plan_purchased",
        `🎉 You’ve successfully purchased the ${plan.name}. Total: ${totalLimit}MB.`
      );

      // ---- NEW: try to enable Tailscale device for user (if one exists) ----
      try {
        const enableRes = await enableVPNAccess(email);
        if (enableRes.ok && enableRes.deviceId) {
          // store device id on user doc for later reference
          await userRef.update({ vpnDeviceId: enableRes.deviceId });
          console.log(`Saved vpnDeviceId=${enableRes.deviceId} to user ${email}`);
        } else {
          console.log("Tailscale enable returned:", enableRes);
        }
      } catch (err) {
        console.warn("Error enabling tailscale device after purchase:", err.message);
      }

      res.sendStatus(200);
    } catch (err) {
      console.error("❌ Webhook error:", err);
      res.sendStatus(500);
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

    // optional: ensure tailscale device enabled when user connects
    try {
      const user = snap.docs[0].data();
      if (user && !user.vpnDeviceId) {
        // attempt to find / enable mapping if vpnDeviceId not set
        const r = await enableVPNAccess(username);
        if (r.ok && r.deviceId) {
          await snap.docs[0].ref.update({ vpnDeviceId: r.deviceId });
        }
      }
    } catch (err) {
      console.warn("connect: tailscale enable attempt failed:", err.message);
    }

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
// Tailscale manual endpoint (testing / admin use)
// ----------------------
app.post("/tailscale/enable-user", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email required" });
    const r = await enableVPNAccess(email);
    if (r.ok) {
      // try to update user doc with device id
      const snap = await db.collection("users").where("email", "==", email).limit(1).get();
      if (!snap.empty && r.deviceId) {
        await snap.docs[0].ref.update({ vpnDeviceId: r.deviceId, vpnActive: true });
      }
      return res.json({ success: true, deviceId: r.deviceId || null });
    } else {
      return res.status(500).json({ success: false, error: r.error || r.reason });
    }
  } catch (err) {
    console.error("/tailscale/enable-user error:", err.message);
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
      { headers: { Authorization: _tailscaleAuthHeader() } }
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
            { method: "POST", headers: { Authorization: _tailscaleAuthHeader() } }
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
