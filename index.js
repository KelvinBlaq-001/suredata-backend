// index.js — SureData Backend (Production-ready, Rollover + Auto-Disconnect)
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import crypto from "crypto";
import fetch from "node-fetch";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

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

// --- Helper: find user by identifier (username | email | phone)
async function findUserDocByIdentifier(identifier) {
  if (!identifier) return null;
  const users = db.collection("users");

  let snap = await users.where("username", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  if (identifier.includes("@")) {
    snap = await users
      .where("email", "==", identifier.toLowerCase())
      .limit(1)
      .get();
    if (!snap.empty) return snap.docs[0];
  }

  snap = await users.where("phone", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  return null;
}

// ---- Health ----
app.get("/health", (req, res) => res.status(200).send("OK"));

// ---- ADMIN SUMMARY ----
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

// ---------------------------- 
// PAYSTACK WEBHOOK (with rollover logic)
// ----------------------------
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;

      const rawBody = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(JSON.stringify(req.body));

      // Verify signature
      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(rawBody)
        .digest("hex");
      const receivedHash = req.headers["x-paystack-signature"];

      if (computedHash !== receivedHash) {
        console.warn("⚠️ Invalid Paystack signature");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      console.log("📩 Paystack event:", event.event);

      if (event.event === "charge.success") {
        const data = event.data;
        const reference = data.reference;
        const amount = data.amount / 100;
        const email = data.customer.email;

        console.log(`💰 Payment from ${email}: ₦${amount}`);

        // Firestore: Find user
        const usersRef = db.collection("users");
        const snapshot = await usersRef.where("email", "==", email).limit(1).get();

        if (snapshot.empty) {
          console.warn("⚠️ No user found for:", email);
          return res.sendStatus(200);
        }

        const userDoc = snapshot.docs[0];
        const userRef = userDoc.ref;
        const user = userDoc.data();

        // Available plans
        const plans = {
          500: { name: "1GB", dataLimit: 1 * 1024, days: 30 },
          1000: { name: "3GB", dataLimit: 3 * 1024, days: 30 },
          2000: { name: "8GB", dataLimit: 8 * 1024, days: 30 },
          5000: { name: "20GB", dataLimit: 20 * 1024, days: 30 },
        };

        const plan = plans[amount];
        if (!plan) {
          console.warn(`⚠️ Unknown plan amount: ₦${amount}`);
          return res.sendStatus(200);
        }

        // Start transaction
        await db.runTransaction(async (t) => {
          const doc = await t.get(userRef);
          const u = doc.data();

          let currentDataUsed = u.dataUsed || 0;
          let currentPlanLimit = u.planLimit || 0;
          let currentExpiry = u.expiryDate ? new Date(u.expiryDate) : null;
          let now = new Date();

          // ✅ Check if current plan still active (not expired)
          const isPlanActive = currentExpiry && currentExpiry > now;

          // ✅ New plan expiry
          const newExpiry = new Date();
          newExpiry.setDate(newExpiry.getDate() + plan.days);

          let finalPlanLimit, finalExpiry;

          if (isPlanActive) {
            // Plan still active → rollover
            const remainingData = Math.max(currentPlanLimit - currentDataUsed, 0);
            finalPlanLimit = remainingData + plan.dataLimit;

            // Option A: Keep old expiry if it's later
            // Option B (Rollover): Extend expiry to new plan date
            finalExpiry = newExpiry > currentExpiry ? newExpiry : currentExpiry;

            console.log(`🔄 Rollover applied for ${email}: ${remainingData}MB + ${plan.dataLimit}MB`);
          } else {
            // Old plan expired → reset everything
            finalPlanLimit = plan.dataLimit;
            finalExpiry = newExpiry;

            console.log(`🆕 New plan started for ${email}: ${plan.dataLimit}MB`);
          }

          // Update user
          const updates = {
            balance: (u.balance || 0) + amount,
            currentPlan: plan.name,
            planLimit: finalPlanLimit,
            dataUsed: 0,
            expiryDate: finalExpiry.toISOString(),
            vpnActive: true,
            lastPayment: {
              reference,
              amount,
              date: new Date().toISOString(),
            },
          };

          t.update(userRef, updates);

          // Log transaction
          const txRef = db.collection("transactions").doc(reference);
          t.set(txRef, {
            uid: userDoc.id,
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

      res.sendStatus(200);
    } catch (error) {
      console.error("❌ Webhook error:", error.message);
      res.sendStatus(500);
    }
  }
);


// ✅ Re-enable JSON parsing for other routes
app.use(express.json());

// ---- Helper: Disable VPN Access ----
async function disableVPNAccess(username) {
  try {
    const vpnAPI = process.env.VPN_DISABLE_ENDPOINT; // e.g. "http://127.0.0.1:8081/vpn/disable"
    if (!vpnAPI) {
      console.warn("⚠️ No VPN_DISABLE_ENDPOINT set in .env");
      return;
    }

    const res = await fetch(vpnAPI, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });

    if (!res.ok) {
      console.warn(`⚠️ Failed to disable VPN for ${username} (${res.status})`);
    } else {
      console.log(`🛑 VPN access disabled for ${username}`);
    }
  } catch (err) {
    console.error("❌ disableVPNAccess error:", err.message);
  }
}


// ---- VPN SESSION CONNECT ----
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    console.log("🟢 VPN Connect triggered for:", username, vpn_ip);

    const snapshot = await db
      .collection("users")
      .where("email", "==", username)
      .limit(1)
      .get();

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
    console.log(
      "🔴 VPN Disconnect triggered for:",
      username,
      vpn_ip,
      "Data used:",
      data_used_mb,
      "MB"
    );

    const snapshot = await db
      .collection("users")
      .where("email", "==", username)
      .limit(1)
      .get();

    if (snapshot.empty)
      return res.status(404).json({ error: "User not found" });

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    const updatedDataUsed = (user.dataUsed || 0) + data_used_mb;
    const overLimit = updatedDataUsed >= (user.planLimit || Infinity);
    const expired =
      user.expiryDate && new Date(user.expiryDate) < new Date();

    const updates = {
      dataUsed: updatedDataUsed,
      vpnActive: !overLimit && !expired,
      lastDisconnect: new Date().toISOString(),
    };

    await userDoc.ref.update(updates);
    console.log(
      `✅ Updated user ${username} as disconnected. Total used: ${updatedDataUsed}MB`
    );

    // Auto-disable in Tailscale if needed
    if (overLimit || expired) {
      console.log(`⚠️ Auto-disabling VPN for ${username}`);
}

    }

    res.json({
      success: true,
      username,
      dataUsed: updatedDataUsed,
      overLimit,
      expired,
    });
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

    const snap = await db
      .collection("users")
      .where("email", "==", username)
      .limit(1)
      .get();
    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const userDoc = snap.docs[0];
    const user = userDoc.data();

    const newDataUsed = (user.dataUsed || 0) + usage_mb;
    const overLimit = newDataUsed >= (user.planLimit || Infinity);
    const expired =
      user.expiryDate && new Date(user.expiryDate) < new Date();

    const updates = {
      dataUsed: newDataUsed,
      vpnActive: !overLimit && !expired,
      updatedAt: new Date().toISOString(),
    };

    await userDoc.ref.update(updates);
    console.log(`✅ Updated usage for ${username}. Total: ${newDataUsed}MB`);

    if (overLimit || expired) {
      console.log(`⚠️ Auto-disabling VPN for ${username}`);
      await doc.ref.update({ vpnActive: false });
await disableVPNAccess(u.email || u.username || doc.id);

    }

    res.json({
      success: true,
      username,
      dataUsed: newDataUsed,
      overLimit,
      expired,
    });
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
      const exhausted =
        (u.planLimit || 0) > 0 && (u.dataUsed || 0) >= u.planLimit;

      if (expired || exhausted) {
        await doc.ref.update({ vpnActive: false });
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

// ---- TAILSCALE SYNC CRON (Optional future use) ----
app.all("/cron/tailscale-sync", async (req, res) => {
  try {
    console.log("🔄 Running Tailscale sync (placeholder)...");
    // You can later fetch your Tailscale devices and sync statuses here
    res.status(200).send("✅ Tailscale sync executed (stub)");
  } catch (err) {
    console.error("❌ tailscale-sync error:", err.message);
    res.status(500).send("Error syncing with Tailscale");
  }
});


// ---- Start server ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () =>
  console.log(`🚀 SureData backend running on port ${PORT}`)
);
