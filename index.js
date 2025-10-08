import express from "express";
import dotenv from "dotenv";
import admin from "firebase-admin";
import { readFileSync } from "fs";

dotenv.config();
const app = express();
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));


// --- FIREBASE ADMIN SETUP ---
const serviceAccount = {
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ---------------------------- 
// PAYSTACK WEBHOOK (FINAL STABLE VERSION)
// ----------------------------
import crypto from "crypto";

app.post(
  "/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;

      // Get raw body safely
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
        const amount = data.amount / 100; // Paystack sends amount in kobo → convert to naira
        const email = data.customer.email;

        console.log(`💰 Payment from ${email}: ₦${amount}`);

        // Firestore: Find user by email
        const usersRef = db.collection("users");
        const snapshot = await usersRef.where("email", "==", email).limit(1).get();

        if (snapshot.empty) {
          console.warn("⚠️ No user found for:", email);
        } else {
          const userDoc = snapshot.docs[0];
          const userRef = userDoc.ref;

          // ✅ Plan mapping (amount → plan info)
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

            // Always update balance
            let updates = {
              balance: (user.balance || 0) + amount,
              lastPayment: {
                reference,
                amount,
                date: new Date().toISOString(),
              },
            };

            // If plan purchased, activate
            if (plan) {
              const expiryDate = new Date();
              expiryDate.setDate(expiryDate.getDate() + plan.days);

              updates = {
                ...updates,
                currentPlan: plan.name,
                planLimit: plan.dataLimit,
                dataUsed: 0,
                expiryDate: expiryDate.toISOString(),
                vpnActive: true,
              };

              console.log(`✅ Assigned plan ${plan.name} to ${email}`);
            } else {
              console.log(`✅ Balance only updated for ${email}`);
            }

            // Update user profile
            t.update(userRef, updates);

            // Record transaction
            const txRef = db.collection("transactions").doc(reference);
            t.set(txRef, {
              uid: userDoc.id,
              email,
              reference,
              amount,
              status: "success",
              plan: plan ? plan.name : null,
              timestamp: new Date().toISOString(),
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




// --- TEST ROUTE ---
app.get("/", (req, res) => {
  res.json({
    success: true,
    data: { status: "ok", time: new Date().toISOString() },
  });
});

// --- CREATE USER PROFILE ---
app.post("/api/createUser", async (req, res) => {
  try {
    const { uid, email } = req.body;
    if (!uid || !email) {
      return res.status(400).json({ error: "uid and email required" });
    }

    const userRef = db.collection("users").doc(uid);
    const doc = await userRef.get();

    if (doc.exists) {
      return res.json({ success: true, message: "User already exists" });
    }

    await userRef.set({
      email,
      balance: 0,
      currentPlan: "none",
      dataUsed: 0,
      planLimit: 0,
      expiryDate: null,
      vpnConfigFile: "",
      createdAt: new Date().toISOString(),
    });

    res.json({ success: true, message: "User profile created" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- GET USER PROFILE ---
app.get("/api/getUser/:uid", async (req, res) => {
  try {
    const userRef = db.collection("users").doc(req.params.uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, data: doc.data() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- UPDATE DATA USAGE ---
app.post("/api/updateUsage", async (req, res) => {
  try {
    const { uid, usedMB } = req.body;
    if (!uid || usedMB == null) {
      return res.status(400).json({ error: "uid and usedMB required" });
    }

    const userRef = db.collection("users").doc(uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = doc.data();
    const newUsed = (user.dataUsed || 0) + usedMB;

    await userRef.update({ dataUsed: newUsed });
    res.json({ success: true, newUsage: newUsed });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- SET PLAN AFTER PAYMENT ---
app.post("/api/setPlan", async (req, res) => {
  try {
    const { uid, plan } = req.body;
    if (!uid || !plan) {
      return res.status(400).json({ error: "uid and plan required" });
    }

    const plans = {
      "N500": { limit: 1, price: 500 },
      "N1000": { limit: 3, price: 1000 },
      "N2000": { limit: 8, price: 2000 },
      "N5000": { limit: 20, price: 5000 },
    };

    const selected = plans[plan];
    if (!selected) return res.status(400).json({ error: "Invalid plan" });

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 30);

    await db.collection("users").doc(uid).update({
      currentPlan: plan,
      planLimit: selected.limit,
      expiryDate: expiryDate.toISOString(),
      dataUsed: 0,
    });

    res.json({ success: true, message: "Plan updated", plan: selected });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ SureData backend running on port ${PORT}`));

