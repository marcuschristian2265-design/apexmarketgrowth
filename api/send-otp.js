const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { getAdmin, authUser } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  let stage = 'start';
  try {
    const missing = ['FIREBASE_SERVICE_ACCOUNT','SMTP_USER','SMTP_PASS'].filter(k => !process.env[k]);
    if (missing.length) return res.status(500).json({ error: 'Server setup incomplete (missing: ' + missing.join(', ') + ').' });
    stage = 'auth';
    const user = await authUser(req);
    if (!user || !user.email) return res.status(401).json({ error: 'Please sign in again.' });

    stage = 'firestore';
    const db = getAdmin().firestore();
    const ref = db.collection('emailOtps').doc(user.uid);
    const snap = await ref.get();
    if (snap.exists && Date.now() - snap.data().sentAt < 45000) {
      return res.status(429).json({ error: 'Please wait a moment before requesting another code.' });
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const hash = crypto.createHash('sha256').update(code + user.uid).digest('hex');
    await ref.set({ hash, expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0, sentAt: Date.now() });

    stage = 'email';
    const transporter = nodemailer.createTransport({
      host: String(process.env.SMTP_HOST || 'smtp.zoho.com').split('=').pop().replace(/\s+/g, ''),
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });

    await transporter.sendMail({
      from: `"ApexMarketGrowth" <${process.env.SMTP_USER}>`,
      to: user.email,
      subject: `${code} is your ApexMarketGrowth verification code`,
      text: `Your verification code is ${code}. It expires in 10 minutes. If you did not request this, ignore this email.`,
      html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f3f4f6">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 12px"><tr><td align="center">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:16px;overflow:hidden;font-family:Arial,Helvetica,sans-serif">
    <tr><td style="background:#861535;padding:26px 32px;text-align:center">
      <span style="font-size:30px;font-weight:900;letter-spacing:6px;color:#ffffff">AMG.</span>
      <div style="font-size:12px;color:#f3c9d4;margin-top:4px;letter-spacing:1px">ApexMarketGrowth</div>
    </td></tr>
    <tr><td style="padding:36px 32px 12px;text-align:center">
      <h1 style="margin:0 0 10px;font-size:22px;color:#111827">Verify your email address</h1>
      <p style="margin:0;font-size:14px;line-height:22px;color:#6b7280">Enter this code on the verification page to finish creating your account.</p>
    </td></tr>
    <tr><td style="padding:16px 32px;text-align:center">
      <div style="display:inline-block;background:#fdf2f5;border:2px dashed #861535;border-radius:14px;padding:18px 28px">
        <span style="font-size:38px;font-weight:800;letter-spacing:12px;color:#861535;font-family:'Courier New',monospace">${code}</span>
      </div>
      <p style="margin:16px 0 0;font-size:13px;color:#6b7280">This code expires in <strong>10 minutes</strong>.</p>
    </td></tr>
    <tr><td style="padding:12px 32px 32px">
      <div style="background:#f9fafb;border-radius:10px;padding:14px 16px;font-size:12px;line-height:19px;color:#6b7280">
        <strong style="color:#374151">Never share this code.</strong> ApexMarketGrowth will never ask you for it by phone, chat or email. If you didn't create an account, you can safely ignore this message.
      </div>
    </td></tr>
    <tr><td style="background:#f9fafb;padding:18px 32px;text-align:center;font-size:12px;color:#9ca3af;border-top:1px solid #eef0f3">
      Need help? Contact <a href="mailto:support@apexmarketgrowth.org" style="color:#861535;text-decoration:none">support@apexmarketgrowth.org</a><br>© ApexMarketGrowth
    </td></tr>
  </table>
</td></tr></table></body></html>`
    });

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('send-otp failed:', e && e.code, e && e.message);
    res.status(500).json({ error: 'Could not send the code (' + (typeof stage !== 'undefined' ? stage : 'unknown') + (e && e.code ? ': ' + e.code : '') + '). Please try again.' });
  }
};
