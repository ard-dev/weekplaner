const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();

exports.verifyPassword = onRequest(
  { region: "europe-west1", secrets: ["PASS_HASH"], invoker: "public" },
  (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }

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
    if (hash !== process.env.PASS_HASH) {
      res.status(401).json({ error: "Wrong password" });
      return;
    }

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
