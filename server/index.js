const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server")
const express = require("express")
const cors = require("cors")
const cookieParser = require("cookie-parser")
const { getUserByEmail, getUserById, createUser, updateUserCounter } = require("./db.js")
const app = express()
app.use(express.json())
app.use(cookieParser())

app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }))
app.get("/init-regisration", async (req, res) => {
  const email = req.query.email
  if (!email) {
    return res.status(400).json({
      error: "Email is Required",
    })
  }
  if (getUserByEmail(email) !== null) {
    return res.status(400).json({
      error: "User is already exists",
    })
  }
  const options = await generateRegistrationOptions({
    rpID: process.env.RP_ID,
    rpName: "test",
    userName: email,
  })
  res.cookie(
    "regInfo",
    JSON.stringify({
      userId: options.user.id,
      email,
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  )
  options.challenge
  res.json(options)
})
app.post("/verify-regisration", async (req, res) => {
  const regInfo = JSON.parse(req.cookies.regInfo)
  if (!regInfo) {
    return res.status(400).json({ error: "Reqistration Info is not found" })
  }
  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: regInfo.challenge,
    expectedOrigin: process.env.CLIENT_URL,
    expectedRPID: process.env.RP_ID,
  })
  if (verification.verified) {
    createUser(regInfo.userId, regInfo.email, {
      id: verification.registrationInfo.credentialID,
      publicKey: verification.registrationInfo.credentialPublickKey,
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transport: req.body.transports,
    })
    res.clearCookie("regInfo")
    return res.json({ verified: verification.verified })
  } else {
    return res.status(400).json({ verified: false, error: "Verification failed" })
  }
})
app.get("/init-auth", async (req, res) => {
  const email = req.query.email
  if (!email) {
    return res.status(400).json({
      error: "Email is Required",
    })
  }
  const user = getUserByEmail(email)
  if (user == null) {
    return res.status(400).json({
      error: "No user for this email",
    })
  }
  const options = await generateRegistrationOptions({
    rpID: process.env.RP_ID,
    allowCredentials: [
      {
        id: user.passKey.id,
        type: "public-key",
        transports: user.passKey.transports,
      },
    ],
  })
  res.cookie(
    "authInfo",
    JSON.stringify({
      userId: user.id,
      email,
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  )
  res.json(options)
})
app.get("verify-auth", async (req, res) => {
  if (user == null || user.passKey.id !== req.body.id) {
    res.status(400).json({ error: "Invalid User" })
  }
  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: authInfo.challenge,
    expectedOrigin: process.env.CLIENT_URL,
    expectedRPID: process.env.RP_ID,
    authticator: {
      credentialID: user.passKey.id,
      credentialPublickKey: user.passKey.publicKey,
      counter: user.passKey.counter,
      transports: user.passKey.transports,
    },
  })
  if (verification.verified) {
    updateUserCounter(user.id,verification.authenticationInfo.newCounter)
    res.clearCookie("authInfo")
    //here need to save them in session cookie
    return res.json({ verified: verification.verified })
  } else {
    return res.status(400).json({ verified: false, error: "Verification failed" })
  }
})
app.listen(3000, () => {
  console.log("Server is Listening on http://localhost:3000")
})
