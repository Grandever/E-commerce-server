const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const otpModel = require("../models/otp.model");

function normalizeEmail(email) {
  if (!email || typeof email !== "string") return null;
  const s = email.trim().toLowerCase();
  return s.length ? s : null;
}

class MailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });
  }

  async sendOtpMail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) {
      throw new Error("Invalid email address");
    }

    const otp = Math.floor(100000 + Math.random() * 900000); // 6 digit OTP
    console.log("OTP:", otp, "→", normalized);

    const hashedOtp = await bcrypt.hash(otp.toString(), 10);
    await otpModel.deleteMany({ email: normalized });
    await otpModel.create({
      email: normalized,
      otp: hashedOtp,
      expireAt: new Date(Date.now() + 1 * 60 * 1000),
    });

    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_USER,
        to: normalized,
        subject: `OTP for verification ${new Date().toLocaleString()}`,
        html: `
				<h1>Your OTP is ${otp}</h1>
				<p>OTP will expire in 5 minutes</p>
				<p><strong>Note:</strong> Do not share this OTP with anyone for security reasons.</p>
			`,
      });
    } catch (mailErr) {
      await otpModel.deleteMany({ email: normalized });
      const msg =
        mailErr?.response ||
        mailErr?.message ||
        "Could not send email. Check SMTP settings.";
      throw new Error(
        typeof msg === "string" ? msg : "Could not send OTP email"
      );
    }
  }

  async verifyOtp(email, otp) {
    const normalized = normalizeEmail(email);
    if (!normalized) return { failure: "Record not found" };

    const lastRecord = await otpModel
      .findOne({ email: normalized })
      .sort({ _id: -1 });
    if (!lastRecord) return { failure: "Record not found" };
    if (!lastRecord.otp || typeof lastRecord.otp !== "string") {
      return { failure: "Record not found" };
    }
    if (lastRecord.expireAt < new Date()) return { status: 301 };

    const isValid = await bcrypt.compare(otp, lastRecord.otp);
    if (!isValid) return { failure: "Invalid OTP" };

    await otpModel.deleteMany({ email: normalized });
    return { status: 200 };
  }
}

module.exports = new MailService();
