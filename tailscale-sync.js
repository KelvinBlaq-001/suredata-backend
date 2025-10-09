import fetch from "node-fetch";
import admin from "firebase-admin";
import dotenv from "dotenv";
dotenv.config();

const firestore = admin.firestore();
const API_KEY = process.env.TAILSCALE_API_KEY;
const TAILNET = process.env.TAILSCALE_TAILNET;
const API_BASE = `https://api.tailscale.com/api/v2/tailnet/${TAILNET}`;

// Utility for authenticated requests
async function tailscaleRequest(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    ...options,
  });
  if (!res.ok) {
    const err = await res.text();
    console.error(`❌ Tailscale API error: ${res.status} ${err}`);
  }
  return res.json().catch(() => ({}));
}

// 🟢 Sync Firestore -> Tailscale
export async function syncUsersToTailscale() {
  try {
    console.log("🔄 Syncing users with Tailscale...");

    const usersSnap = await firestore.collection("users").get();
    for (const doc of usersSnap.docs) {
      const user = doc.data();

      // Skip inactive or expired users
      if (!user.vpnActive || new Date(user.expiryDate) < new Date()) continue;

      // Ensure user device is allowed on Tailscale ACLs (pseudo logic)
      await tailscaleRequest(`/devices/allow/${user.username}`, {
        method: "POST",
      });
    }

    console.log("✅ Sync completed.");
  } catch (err) {
    console.error("❌ Sync error:", err);
  }
}

// 🔴 Remove expired users/devices
export async function cleanUpExpiredUsers() {
  try {
    const usersSnap = await firestore.collection("users").get();
    for (const doc of usersSnap.docs) {
      const user = doc.data();

      if (new Date(user.expiryDate) < new Date()) {
        await tailscaleRequest(`/devices/disable/${user.username}`, {
          method: "POST",
        });
        await doc.ref.update({ vpnActive: false });
        console.log(`🛑 Disabled expired user: ${user.username}`);
      }
    }
  } catch (err) {
    console.error("❌ Cleanup error:", err);
  }
}
