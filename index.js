const express = require("express");
const dotenv = require("dotenv");
const { prisma } = require("./db/config");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
dotenv.config();

const app = express();

app.use(express.json());

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "not valid input" });
  }
  const isUserExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (isUserExists) {
    return res.status(400).json({ error: "Email already in use" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword,
      name,
    },
  });
  return res
    .status(201)
    .json({ message: "User created successfully", userId: user.id });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "not valid input" });
  }
  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!user) {
    return res.status(400).json({ error: "Email not found" });
  }

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) {
    return res.status(400).json({ error: "wrongpassword" });
  }

  const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET);

  return res.status(200).json({ userdata: user, accesstoken: accessToken });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports = app;
