// index.js - SureData backend (final updated)
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
const firestore = admin.firestore();

// --- Helper: find user by identifier (username | email | phone)
async function findUserDocByIdentifier(identifier) {
  if (!identifier) return null;
  const users = firestore.collection("users");

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

// ---- Root route ----
app.get("/", (req, res) => {
  res.json({ success: true, message: "SureData backend running" });
});

// ---- PAYSTACK WEBHOOK ----
// Note: Paystack sends amount in kobo. We divide by 100 to get Naira.
app.post("/payments/webhook", async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    if (!secret) return res.status(500).send("Missing Paystack secret");

    // Compute HMAC from JSON string (works if your incoming JSON formatting matches Paystack's)
    const hash = crypto.createHmac("sha512", secret).update(JSON.stringify(req.body)).digest("hex");
    if (hash !== req.headers["x-paystack-signature"]) {
      console.warn("Invalid Paystack signature");
      return res.status(400).send("Invalid signature");
    }

    const event = req.body.event;
    const data = req.body.data;

    if (event === "charge.success") {
      const email = data.customer?.email?.toLowerCase?.() || null;
      const phone = data.customer?.phone || null;
      const amount = data.amount / 100; // to Naira
      const reference = data.reference;

      console.log(`Paystack charge.success: ${email || phone} ₦${amount}`);

      // resolve user by email or phone (prefer email)
      let userDoc = null;
      if (email) userDoc = await findUserDocByIdentifier(email);
      if (!userDoc && phone) userDoc = await findUserDocByIdentifier(phone);

      if (!userDoc) {
        console.warn("No user found for payment:", email || phone);
        // still record transaction
        await firestore.collection("transactions").doc(reference).set({
          email: email || null,
          phone: phone || null,
          reference,
          amount,
          status: "success",
          plan: null,
          timestamp: new Date().toISOString(),
        });
        return res.status(200).send("User not found - transaction recorded");
      }

      const userRef = userDoc.ref;
      const user = userDoc.data();

      // Plan mapping (Naira -> MB)
      const plans = {
        500: { name: "N500", dataLimitMB: 1024, days: 30 },     // 1 GB
        1000: { name: "N1000", dataLimitMB: 3072, days: 30 },   // 3 GB
        2000: { name: "N2000", dataLimitMB: 8192, days: 30 },   // 8 GB
        5000: { name: "N5000", dataLimitMB: 20480, days: 30 },  // 20 GB
      };

      const plan = plans[amount] || null;

      // Perform transaction atomically
      await firestore.runTransaction(async (t) => {
        const snapshot = await t.get(userRef);
        if (!snapshot.exists) throw new Error("User disappeared");
        const u = snapshot.data();

        // credit balance (optional)
        const newBalance = (u.balance || 0) + amount;

        const updates = {
          balance: newBalance,
          lastPayment: { reference, amount, date: new Date().toISOString() },
        };

        if (plan) {
          // Auto-renew: extend expiry if still active, or set new expiry
          const now = new Date();
          const oldExpiry = u.expiryDate ? new Date(u.expiryDate) : null;
          let expiryDate;
          if (oldExpiry && oldExpiry > now) {
            expiryDate = new Date(oldExpiry.getTime() + plan.days * 24 * 60 * 60 * 1000);
          } else {
            expiryDate = new Date(now.getTime() + plan.days * 24 * 60 * 60 * 1000);
          }

          updates.currentPlan = plan.name;
          // stack data: add plan data to existing remaining quota
          updates.planLimit = (u.planLimit || 0) + plan.dataLimitMB;
          updates.dataUsed = 0; // optionally reset or keep prior usage — we reset here for cleaner UX
          updates.expiryDate = expiryDate.toISOString();
          updates.vpnActive = true;
        }

        t.update(userRef, updates);

        // record transaction doc
        const txRef = firestore.collection("transactions").doc(reference);
        t.set(txRef, {
          uid: userRef.id,
          email: u.email || null,
          phone: u.phone || null,
          reference,
          amount,
          status: "success",
          plan: plan ? plan.name : null,
          timestamp: new Date().toISOString(),
        });
      });

      console.log(`✅ Payment processed and ${plan ? "plan applied" : "balance updated"} for user`);
      return res.status(200).send("OK");
    }

    res.status(200).send("Ignored event");
  } catch (err) {
    console.error("Webhook error:", err);
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
      console.warn("Connect: user not found:", username);
      return res.status(404).send("User not found");
    }

    await userDoc.ref.update({
      vpnActive: true,
      lastConnectedIP: vpn_ip || null,
      lastConnectedAt: new Date().toISOString(),
    });

    console.log(`🟢 ${username} connected (IP ${vpn_ip || "unknown"})`);
    res.status(200).send("OK");
  } catch (err) {
    console.error("Connect error:", err);
    res.status(500).send("Server error");
  }
});

// ---- VPN DISCONNECT ----
app.post("/vpn/session/disconnect", async (req, res) => {
  try {
    const { username, bytes_sent = 0, bytes_received = 0, dataUsedMB /* optional */ } = req.body;
    if (!username) return res.status(400).send("Missing username");

    const userDoc = await findUserDocByIdentifier(username);
    if (!userDoc) {
      console.warn("Disconnect: user not found:", username);
      return res.status(404).send("User not found");
    }

    const uSnap = await userDoc.ref.get();
    const user = uSnap.data();

    // determine MB used: prefer explicit dataUsedMB, else compute from bytes
    let usedMB = 0;
    if (typeof dataUsedMB === "number") usedMB = dataUsedMB;
    else usedMB = (Number(bytes_sent || 0) + Number(bytes_received || 0)) / (1024 * 1024);

    const newDataUsed = (user.dataUsed || 0) + usedMB;
    const remaining = (user.planLimit || 0) - newDataUsed;
    const stillActive = remaining > 0 && user.expiryDate && new Date(user.expiryDate) > new Date();

    const updates = {
      dataUsed: newDataUsed,
      vpnActive: stillActive,
      lastDisconnect: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // auto-disable fully if exhausted or expired
    if (!stillActive) {
      updates.vpnActive = false;
      // Optionally clear plan fields:
      // updates.currentPlan = null;
      // updates.planLimit = 0;
    }

    await userDoc.ref.update(updates);

    console.log(`📡 ${username} disconnected — used ${usedMB.toFixed(2)} MB (total ${newDataUsed.toFixed(2)} MB)`);
    res.status(200).send("OK");
  } catch (err) {
    console.error("Disconnect error:", err);
    res.status(500).send("Server error");
  }
});

// ---- AUTO EXPIRE & DATA-EXHAUSTION CHECK ----
app.post("/cron/expire-check", async (req, res) => {
  try {
    const now = new Date();
    const usersSnap = await firestore.collection("users").get();

    for (const doc of usersSnap.docs) {
      const user = doc.data();
      const expired = user.expiryDate && new Date(user.expiryDate) < now;
      const dataExhausted = (user.planLimit || 0) > 0 && (user.dataUsed || 0) >= user.planLimit;

      if (expired || dataExhausted) {
        await doc.ref.update({ vpnActive: false });
        console.log(`🔴 Auto-disabled ${user.username || user.email}: expired(${expired}) dataExhausted(${dataExhausted})`);
      }
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error("Expiry check error:", err);
    res.status(500).send("Server error");
  }
});

// ---- START SERVER ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ SureData backend running on port ${PORT}`));
