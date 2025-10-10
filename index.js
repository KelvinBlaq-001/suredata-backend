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
// PAYSTACK WEBHOOK + ROLLOVER LOGIC
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

        const usersRef = db.collection("users");
        const snapshot = await usersRef
          .where("email", "==", email)
          .limit(1)
          .get();

        if (snapshot.empty) {
          console.warn("⚠️ No user found for:", email);
        } else {
          const userDoc = snapshot.docs[0];
          const userRef = userDoc.ref;

          const plans = {
            500: { name: "1GB", dataLimit: 1 * 1024, days: 30 },
            1000: { name: "3GB", dataLimit: 3 * 1024, days: 30 },
            2000: { name: "8GB", dataLimit: 8 * 1024, days: 30 },
            5000: { name: "20GB", dataLimit: 20 * 1024, days: 30 },
          };

          const plan = plans[amount];

          await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            if (!doc.exists) throw new Error("User not found");

            const user = doc.data();
            const now = new Date();

            let updates = {
              balance: (user.balance || 0) + amount,
              lastPayment: {
                reference,
                amount,
                date: now.toISOString(),
              },
            };

            if (plan) {
              const expiryDate = new Date();
              expiryDate.setDate(expiryDate.getDate() + plan.days);

              // ROLLOVER logic
              let remainingData = 0;
              const oldExpiry = user.expiryDate
                ? new Date(user.expiryDate)
                : null;
              const oldActive = oldExpiry && oldExpiry > now;

              if (oldActive) {
                remainingData = Math.max(
                  (user.planLimit || 0) - (user.dataUsed || 0),
                  0
                );
              }

              const totalData = (plan.dataLimit || 0) + remainingData;

              updates = {
                ...updates,
                currentPlan: plan.name,
                planLimit: totalData,
                dataUsed: 0,
                expiryDate: expiryDate.toISOString(),
                vpnActive: true,
              };

              console.log(
                `✅ Assigned plan ${plan.name} (${totalData}MB total) to ${email}`
              );
            }

            t.update(userRef, updates);

            const txRef = db.collection("transactions").doc(reference);
            t.set(txRef, {
              uid: userDoc.id,
              email,
              reference,
              amount,
              status: "success",
              plan: plan ? plan.name : null,
              timestamp: now.toISOString(),
            });
          });
        }
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
      // you can call your tailscale API disable helper here
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
      // Optional: disable via Tailscale
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
        count++;
      }
    }

    res.status(200).send(`✅ Processed ${usersSnap.size} users, disabled ${count}`);
  } catch (err) {
    console.error("Expiry check error:", err);
    res.status(500).send("Cron error");
  }
});

// ---- Start server ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () =>
  console.log(`🚀 SureData backend running on port ${PORT}`)
);
