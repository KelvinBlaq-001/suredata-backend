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

// --- PAYSTACK WEBHOOK (FINAL FIXED & VERIFIED) ---
import crypto from "crypto";
import bodyParser from "body-parser";

// ✅ Use raw body parser ONLY for this webhook route
app.post("/api/paystack/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const signature = req.headers["x-paystack-signature"];

    if (!secret || !signature) {
      console.error("❌ Missing secret or signature header");
      return res.status(400).send("Missing signature or secret");
    }

    // ✅ Compute HMAC hash using raw buffer
    const hash = crypto.createHmac("sha512", secret).update(req.body).digest("hex");

    if (hash !== signature) {
      console.warn("⚠️ Invalid Paystack signature");
      return res.status(400).send("Invalid signature");
    }

    // ✅ Parse verified event JSON
    const event = JSON.parse(req.body.toString());
    console.log("📩 Paystack event:", event.event);

    if (event.event === "charge.success") {
      const { customer, amount, reference } = event.data;
      const email = customer?.email;

      if (!email) {
        console.warn("⚠️ No customer email in event data");
        return res.sendStatus(400);
      }

      console.log(`💰 Payment received from ${email} → ₦${amount / 100}`);

      // 🔍 Identify plan by amount (amount is in kobo)
      let selectedPlan = null;
      switch (amount) {
        case 50000:
          selectedPlan = "N500";
          break;
        case 100000:
          selectedPlan = "N1000";
          break;
        case 200000:
          selectedPlan = "N2000";
          break;
        case 500000:
          selectedPlan = "N5000";
          break;
      }

      // 🔄 Find Firestore user by email
      const usersRef = db.collection("users");
      const userSnapshot = await usersRef.where("email", "==", email).limit(1).get();

      if (userSnapshot.empty) {
        console.warn("⚠️ User not found for:", email);
      } else {
        const userDoc = userSnapshot.docs[0];
        const userRef = userDoc.ref;

        await db.runTransaction(async (t) => {
          const doc = await t.get(userRef);
          if (!doc.exists) throw new Error("User not found");

          const user = doc.data();
          const expiryDate = new Date();
          expiryDate.setDate(expiryDate.getDate() + 30);

          // ✅ Credit balance or activate plan
          const updates = {
            balance: (user.balance || 0) + amount / 100,
            lastPayment: {
              reference,
              amount: amount / 100,
              date: new Date().toISOString(),
            },
          };

          if (selectedPlan) {
            updates.currentPlan = selectedPlan;
            updates.planLimit =
              selectedPlan === "N500"
                ? 1
                : selectedPlan === "N1000"
                ? 3
                : selectedPlan === "N2000"
                ? 8
                : 20;
            updates.expiryDate = expiryDate.toISOString();
            updates.dataUsed = 0;
          }

          t.update(userRef, updates);

          // Log transaction
          const txRef = db.collection("transactions").doc(reference);
          t.set(txRef, {
            email,
            reference,
            amount: amount / 100,
            status: "success",
            plan: selectedPlan,
            timestamp: new Date().toISOString(),
          });
        });

        console.log(`✅ ${selectedPlan ? "Plan activated" : "Balance updated"} for ${email}`);
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("❌ Webhook error:", error);
    res.sendStatus(500);
  }
});



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

