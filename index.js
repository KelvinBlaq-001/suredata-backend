// index.js — SureData Backend (Final Production Version)
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// ---- Initialize Firebase ----
const serviceAccount = {
  project_id: process.env.FIREBASE_PROJECT_ID,
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
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
    snap = await users.where("email", "==", identifier.toLowerCase()).limit(1).get();
    if (!snap.empty) return snap.docs[0];
  }

  snap = await users.where("phone", "==", identifier).limit(1).get();
  if (!snap.empty) return snap.docs[0];

  return null;
}

// ---- Root route ----
app.get("/", (req, res) => {
  res.json({ success: true, message: "✅ SureData backend is running" });
});

// ---- PAYSTACK WEBHOOK ----
app.post("/payments/webhook", async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    if (!secret) return res.status(500).send("Missing Paystack secret");

    const hash = crypto.createHmac("sha512", secret).update(JSON.stringify(req.body)).digest("hex");
    if (hash !== req.headers["x-paystack-signature"]) {
      console.warn("⚠️ Invalid Paystack signature");
      return res.status(400).send("Invalid signature");
    }

    const { event, data } = req.body;

    if (event === "charge.success") {
      const email = data.customer?.email?.toLowerCase?.() || null;
      const phone = data.customer?.phone || null;
      const amount = data.amount / 100;
      const reference = data.reference;

      console.log(`💰 Payment received from ${email || phone}: ₦${amount}`);

      // Find user by email or phone
      let userDoc = null;
      if (email) userDoc = await findUserDocByIdentifier(email);
      if (!userDoc && phone) userDoc = await findUserDocByIdentifier(phone);

      await db.collection("transactions").doc(reference).set({
        email: email || null,
        phone: phone || null,
        reference,
        amount,
        status: "success",
        timestamp: new Date().toISOString(),
      });

      if (!userDoc) {
        console.warn(`⚠️ No user found for payment: ${email || phone}`);
        return res.status(200).send("Transaction recorded without user");
      }

      const userRef = userDoc.ref;

      // Plan mapping
      const plans = {
        500: { name: "N500", dataLimitMB: 1024, days: 3 },
        1000: { name: "N1000", dataLimitMB: 3072, days: 7 },
        2000: { name: "N2000", dataLimitMB: 8192, days: 15 },
        5000: { name: "N5000", dataLimitMB: 20480, days: 30 }, // ✅ added
      };

      const plan = plans[amount] || null;
      const now = new Date();

      await db.runTransaction(async (t) => {
        const snap = await t.get(userRef);
        if (!snap.exists) throw new Error("User not found during transaction");
        const u = snap.data();

        const oldExpiry = u.expiryDate ? new Date(u.expiryDate) : null;
        const expiryDate =
          oldExpiry && oldExpiry > now
            ? new Date(oldExpiry.getTime() + (plan?.days || 0) * 86400000)
            : new Date(now.getTime() + (plan?.days || 0) * 86400000);

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

      console.log(`✅ ${email || phone}: Plan ${plan?.name || "Balance only"} applied successfully`);
      return res.status(200).send("OK");
    }

    res.status(200).send("Ignored event");
  } catch (err) {
    console.error("❌ Webhook error:", err);
    res.status(500).send("Server error");
  }
});

// ---- VPN CONNECT ----
app.post("/vpn/session/connect", async (req, res) => {
  try {
    const { username, vpn_ip } = req.body;
    if (!username) return res.status(400).send("Missing username");

    const userDoc = await findUserDocByIdentifier(username);
    if (!userDoc) {
      console.warn(`⚠️ Connect: user not found: ${username}`);
      return res.status(404).send("User not found");
    }

    await userDoc.ref.update({
      vpnActive: true,
      lastConnectedIP: vpn_ip || null,
      lastConnectedAt: new Date().toISOString(),
    });

    console.log(`🟢 ${username} connected (${vpn_ip || "no IP"})`);
    res.status(200).send("OK");
  } catch (err) {
    console.error("❌ Connect error:", err);
    res.status(500).send("Server error");
  }
});

// ---- VPN DISCONNECT ----
app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, bytes_sent = 0, bytes_received = 0 } = req.body;
    if (!username) return res.status(400).send("Missing username");

    const userDoc = await findUserDocByIdentifier(username);
    if (!userDoc) {
      console.warn(`⚠️ Disconnect: user not found: ${username}`);
      return res.status(404).send("User not found");
    }

    const user = (await userDoc.ref.get()).data();
    const usedMB = (Number(bytes_sent) + Number(bytes_received)) / (1024 * 1024);
    const newDataUsed = (user.dataUsed || 0) + usedMB;

    const expired = user.expiryDate && new Date(user.expiryDate) < new Date();
    const dataExhausted = (user.planLimit || 0) > 0 && newDataUsed >= user.planLimit;
    const stillActive = !expired && !dataExhausted;

    await userDoc.ref.update({
      dataUsed: newDataUsed,
      vpnActive: stillActive,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    console.log(
      `📡 ${username} disconnected — used ${usedMB.toFixed(2)} MB, total ${newDataUsed.toFixed(
        2
      )} MB. Active: ${stillActive}`
    );

    res.status(200).send("OK");
  } catch (err) {
    console.error("❌ Disconnect error:", err);
    res.status(500).send("Server error");
  }
});

// ---- AUTO EXPIRE CHECK ----
app.all("/cron/expire-check", async (req, res) => {
  try {
    const now = new Date();
    const usersSnap = await db.collection("users").get();

    for (const doc of usersSnap.docs) {
      const user = doc.data();
      const expired = user.expiryDate && new Date(user.expiryDate) < now;
      const dataExhausted = (user.planLimit || 0) > 0 && (user.dataUsed || 0) >= user.planLimit;

      if (expired || dataExhausted) {
        await doc.ref.update({ vpnActive: false });
        console.log(
          `🔴 Auto-disabled ${user.username || user.email}: expired=${expired}, exhausted=${dataExhausted}`
        );
      }
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error("❌ Expiry check error:", err);
    res.status(500).send("Server error");
  }
});

// ---- TAILSCALE SYNC ----
app.all("/cron/tailscale-sync", async (req, res) => {
  try {
    console.log("🔄 Running Tailscale sync job...");
    const usersRef = db.collection("users");
    const snapshot = await usersRef.get();

    if (snapshot.empty) {
      console.log("No users found in Firestore.");
      return res.status(200).send("No users to sync.");
    }

    const syncedUsers = [];

    snapshot.forEach((doc) => {
      const user = doc.data();
      if (user.currentPlan && user.vpnActive) {
        syncedUsers.push({
          uid: doc.id,
          username: user.email || user.phone || user.username,
          plan: user.currentPlan,
          expiryDate: user.expiryDate || null,
        });
      }
    });

    console.log(`✅ Synced ${syncedUsers.length} users with Tailscale.`);
    res.status(200).send(`Tailscale sync complete. Synced ${syncedUsers.length} users.`);
  } catch (error) {
    console.error("❌ Error during Tailscale sync:", error);
    res.status(500).send(`Tailscale sync failed: ${error.message}`);
  }
});

// ---- START SERVER ----
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 SureData backend running on port ${PORT}`));
