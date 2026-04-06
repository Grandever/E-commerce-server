const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const otpModel = require("../models/otp.model");
const otpTemplate = require('../template/otp.template')
const successTemplate = require('../template/success.template')
const cancelTemplate = require('../template/cancel.template')
const updateTemplate = require('../template/update.template')

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

    const otp = Math.floor(100000 + Math.random() * 900000)

    const hashedOtp = await bcrypt.hash(otp.toString(), 10);
    await otpModel.deleteMany({ email: normalized });
    await otpModel.create({
      email: normalized,
      otp: hashedOtp,
      expireAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_USER,
        to: normalized,
        subject: `OTP for verification ${new Date().toLocaleString()}`,
        html: otpTemplate(otp),
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

  async sendSuccessMail({ user, product }) {
    await this.transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: `Order Confirmation ${new Date().toLocaleString()}`,
      html: successTemplate({ user, product }),
    })
  }

  async sendCancelMail({ user, product }) {
    await this.transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: `Order Cancelled ${new Date().toLocaleString()}`,
      html: cancelTemplate({ user, product }),
    })
  }

  async sendUpdateMail({ user, product, status }) {
    await this.transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: `Order Update ${new Date().toLocaleString()}`,
      html: updateTemplate({ user, product, status }),
    })
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
