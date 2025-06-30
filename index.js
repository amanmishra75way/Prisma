const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

dotenv.config();
const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "secret";

// 🔹 Welcome
app.get("/", (req, res) => {
  res.send("API is running");
});

// 🔹 Register User + Create Subscription (inactive)
app.post("/api/register", async (req, res) => {
  const { email, name, password, role } = req.body;
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      email,
      name,
      password: hashed,
      role,
      subscription: {
        create: {
          isActive: false,
        },
      },
    },
    include: {
      subscription: true,
    },
  });

  res.status(201).json({ user });
});

app.patch("/api/activate-subscription/:userId", async (req, res) => {
  const userId = parseInt(req.params.userId);

  const updated = await prisma.userSubscription.updateMany({
    where: { userId },
    data: { isActive: true },
  });

  if (updated.count === 0) return res.status(404).json({ error: "User not found" });
  res.json({ message: "Subscription activated" });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email },
    include: { subscription: true },
  });

  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  if (!user.subscription?.isActive) {
    return res.status(403).json({ error: "Subscription not active" });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ token });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
