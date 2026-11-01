const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { getAdmin, authUser } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const user = await authUser(req);
    if (!user || !user.email) return res.status(401).json({ error: 'Please sign in again.' });

    const db = getAdmin().firestore();
    const ref = db.collection('emailOtps').doc(user.uid);
    const snap = await ref.get();
    if (snap.exists && Date.now() - snap.data().sentAt < 45000) {
      return res.status(429).json({ error: 'Please wait a moment before requesting another code.' });
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const hash = crypto.createHash('sha256').update(code + user.uid).digest('hex');
    await ref.set({ hash, expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0, sentAt: Date.now() });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.zoho.com',
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });

    await transporter.sendMail({
      from: `"ApexMarketGrowth" <${process.env.SMTP_USER}>`,
      to: user.email,
      subject: `${code} is your ApexMarketGrowth verification code`,
      text: `Your verification code is ${code}. It expires in 10 minutes. If you did not request this, ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px">
        <h2 style="color:#861535;margin:0 0 8px">AMG.</h2>
        <p style="color:#333">Use this code to verify your email address:</p>
        <div style="font-size:34px;font-weight:800;letter-spacing:8px;color:#111;margin:16px 0">${code}</div>
        <p style="color:#666;font-size:13px">This code expires in 10 minutes. If you didn't create an ApexMarketGrowth account, you can ignore this email.</p></div>`
    });

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('send-otp', e);
    res.status(500).json({ error: 'Could not send the code. Please try again.' });
  }
};
