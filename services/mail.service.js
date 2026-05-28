const bcrypt = require("bcrypt");
const { Resend } = require("resend");
const otpModel = require("../models/otp.model");
const otpTemplate = require('../template/otp.template');
const successTemplate = require('../template/success.template');
const cancelTemplate = require('../template/cancel.template');
const updateTemplate = require('../template/update.template');

const resend = new Resend(process.env.RESEND_API_KEY);

function normalizeEmail(email) {
  if (!email || typeof email !== "string") return null;
  const s = email.trim().toLowerCase();
  return s.length ? s : null;
}

class MailService {

  async #send({ to, subject, html }) {
    const { error } = await resend.emails.send({
      from: process.env.MAIL_FROM,
      to,
      subject,
      html,
    });
    if (error) throw new Error(error.message);
  }

  async sendOtpMail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) throw new Error("Invalid email address");

    const startedAt = Date.now();
    const otp = Math.floor(100000 + Math.random() * 900000);
    const hashedOtp = await bcrypt.hash(otp.toString(), 10);

    await otpModel.deleteMany({ email: normalized });
    await otpModel.create({
      email: normalized,
      otp: hashedOtp,
      expireAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    try {
      console.log("[TOZA O'ZGARISH] Sending OTP", { to: normalized });

      await this.#send({
        to: normalized,
        subject: `OTP for verification ${new Date().toLocaleString()}`,
        html: otpTemplate(otp),
      });

      console.log("[mail] OTP sent", {
        to: normalized,
        durationMs: Date.now() - startedAt,
      });
    } catch (mailErr) {
      await otpModel.deleteMany({ email: normalized });
      console.error("[mail] OTP send failed", {
        to: normalized,
        durationMs: Date.now() - startedAt,
        message: mailErr?.message,
      });
      throw new Error(mailErr?.message || "Could not send OTP email");
    }
  }

  async sendSuccessMail({ user, product }) {
    await this.#send({
      to: user.email,
      subject: `Order Confirmation ${new Date().toLocaleString()}`,
      html: successTemplate({ user, product }),
    });
  }

  async sendCancelMail({ user, product }) {
    await this.#send({
      to: user.email,
      subject: `Order Cancelled ${new Date().toLocaleString()}`,
      html: cancelTemplate({ user, product }),
    });
  }

  async sendUpdateMail({ user, product, status }) {
    await this.#send({
      to: user.email,
      subject: `Order Update ${new Date().toLocaleString()}`,
      html: updateTemplate({ user, product, status }),
    });
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