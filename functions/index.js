const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/v2/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();

const passHash = defineSecret("PASS_HASH");

exports.verifyPassword = onRequest(
  { cors: true, region: "europe-west1", secrets: [passHash] },
  (req, res) => {
    if (req.method !== "POST") {
      res.status(405).send("Method Not Allowed");
      return;
    }

    const { password } = req.body;
    if (!password) {
      res.status(400).json({ error: "Password required" });
      return;
    }

    const hash = crypto.createHash("sha256").update(password).digest("hex");
    if (hash !== passHash.value()) {
      res.status(401).json({ error: "Wrong password" });
      return;
    }

    // Password correct — create a custom token for a fixed UID
    admin
      .auth()
      .createCustomToken("planner-user")
      .then((token) => res.json({ token }))
      .catch((err) => {
        console.error("Token creation failed:", err);
        res.status(500).json({ error: "Token creation failed" });
      });
  }
);
