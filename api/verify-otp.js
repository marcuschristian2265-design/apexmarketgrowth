const crypto = require('crypto');
const { getAdmin, authUser } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const user = await authUser(req);
    if (!user) return res.status(401).json({ error: 'Please sign in again.' });
    const code = String((req.body && req.body.code) || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code.' });

    const adm = getAdmin();
    const db = adm.firestore();
    const ref = db.collection('emailOtps').doc(user.uid);
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ error: 'No code found. Please request a new one.' });
    const d = snap.data();
    if (Date.now() > d.expiresAt) return res.status(400).json({ error: 'This code has expired. Please request a new one.' });
    if (d.attempts >= 5) return res.status(429).json({ error: 'Too many attempts. Please request a new code.' });

    const hash = crypto.createHash('sha256').update(code + user.uid).digest('hex');
    if (hash !== d.hash) {
      await ref.update({ attempts: d.attempts + 1 });
      return res.status(400).json({ error: 'Incorrect code. Please try again.' });
    }

    await adm.auth().updateUser(user.uid, { emailVerified: true });
    await db.collection('users').doc(user.uid).update({ otpPending: false, emailVerified: true });
    await ref.delete();
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('verify-otp', e);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
};
