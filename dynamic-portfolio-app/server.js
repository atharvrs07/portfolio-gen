require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const nodemailer = require("nodemailer");
const multer = require("multer");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const { customAlphabet } = require("nanoid");

const app = express();
const PORT = process.env.PORT || 4000;
const nanoid = customAlphabet("abcdefghijklmnopqrstuvwxyz0123456789", 8);

const TRACKING_SECRET =
  process.env.TRACKING_SECRET ||
  process.env.SESSION_SECRET ||
  "liquilink-outbound-dev";
const VCARD_REDIRECT_URL = (process.env.VCARD_REDIRECT_URL || "").trim();

const dbFile = path.join(__dirname, "data", "portfolio-db.json");
const adapter = new JSONFile(dbFile);
const db = new Low(adapter, { portfolios: [], users: [] });

const razorpayKeyId = process.env.RAZORPAY_KEY_ID || "";
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET || "";

const razorpay =
  razorpayKeyId && razorpayKeySecret
    ? new Razorpay({
        key_id: razorpayKeyId,
        key_secret: razorpayKeySecret
      })
    : null;

const PLAN_SCHEMA_VERSION = 2;
const PLAN_DEFINITIONS = {
  free: {
    key: "free",
    label: "Free",
    priceINR: 0,
    durationDays: 0
  },
  plus: {
    key: "plus",
    label: "Plus",
    priceINR: 450,
    durationDays: 30
  },
  pro: {
    key: "pro",
    label: "Pro",
    // Approx conversion for USD 20/month at ~INR 83.5 per USD.
    priceINR: 1670,
    durationDays: 30
  }
};

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_COOLDOWN_MS = 60 * 1000;
const OTP_BCRYPT_ROUNDS = 8;

const smtpHost = process.env.SMTP_HOST || "";
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpUser = process.env.SMTP_USER || "";
const smtpPass = process.env.SMTP_PASS || "";
const mailFrom =
  process.env.MAIL_FROM || process.env.SMTP_FROM || smtpUser || "";

const mailTransporter =
  smtpHost && smtpUser && smtpPass
    ? nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass }
      })
    : null;

function maskEmail(email) {
  const normalized = (email || "").trim().toLowerCase();
  const at = normalized.indexOf("@");
  if (at < 1) return normalized || "your email";
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  const show = Math.min(2, local.length);
  const hidden = local.length > show ? "***" : "";
  return `${local.slice(0, show)}${hidden}@${domain}`;
}

function escapeHtmlForMail(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function sendSignupOtpEmail(to, otp, fullName) {
  const subject = "Your LiquiLink verification code";
  const safeName = escapeHtmlForMail(fullName);
  const text = `Hi ${fullName},\n\nYour LiquiLink verification code is: ${otp}\n\nIt expires in 10 minutes.\n\nIf you did not sign up, you can ignore this email.`;
  const html = `<p>Hi ${safeName},</p><p>Your LiquiLink verification code is:</p><p style="font-size:1.45rem;font-weight:700;letter-spacing:0.25em;font-family:ui-monospace,monospace;">${otp}</p><p>This code expires in <strong>10 minutes</strong>.</p><p>If you did not sign up, you can ignore this email.</p>`;

  if (!mailTransporter) {
    console.log(
      `[LiquiLink] SMTP not configured — verification code for ${to}: ${otp}`
    );
    return { dev: true };
  }

  await mailTransporter.sendMail({
    from: mailFrom || smtpUser,
    to,
    subject,
    text,
    html
  });

  return { dev: false };
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const imageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
      cb(null, `${Date.now()}-${nanoid()}${ext}`);
    }
  }),
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype || !file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed."));
    }
    cb(null, true);
  },
  limits: {
    fileSize: 5 * 1024 * 1024
  }
});

function handlePortfolioImageUpload(req, res, next) {
  const middleware = imageUpload.fields([
    { name: "profileImageFile", maxCount: 1 },
    { name: "companyLogoFile", maxCount: 1 }
  ]);

  middleware(req, res, (err) => {
    if (err) {
      return res.status(400).send(
        err && err.message
          ? err.message
          : "Image upload failed. Please use valid image files."
      );
    }

    const profileImage = req.files?.profileImageFile?.[0];
    const companyLogo = req.files?.companyLogoFile?.[0];

    req.uploadedFilesMeta = {
      profileImageFile: profileImage || null,
      companyLogoFile: companyLogo || null
    };

    next();
  });
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

function splitLines(text) {
  return (text || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function parsePipeRows(text, expectedParts) {
  return splitLines(text)
    .map((line) => line.split("|").map((part) => part.trim()))
    .filter((parts) => parts.length >= expectedParts)
    .map((parts) => parts.slice(0, expectedParts));
}

function parseAboutEntries(req) {
  const titles = Array.isArray(req.body.aboutTitle)
    ? req.body.aboutTitle
    : req.body.aboutTitle
      ? [req.body.aboutTitle]
      : [];
  const descriptions = Array.isArray(req.body.aboutDescription)
    ? req.body.aboutDescription
    : req.body.aboutDescription
      ? [req.body.aboutDescription]
      : [];

  const maxLen = Math.max(titles.length, descriptions.length);
  const out = [];
  for (let i = 0; i < maxLen; i += 1) {
    const title = String(titles[i] || "").trim();
    const description = String(descriptions[i] || "").trim();
    if (!title && !description) continue;
    out.push({ title, description });
  }
  if (out.length > 0) return out;

  return parsePipeRows(req.body.aboutCards, 2).map(([title, description]) => ({
    title,
    description
  }));
}

function parseProjectEntries(req) {
  const titles = Array.isArray(req.body.projectTitle)
    ? req.body.projectTitle
    : req.body.projectTitle
      ? [req.body.projectTitle]
      : [];
  const platforms = Array.isArray(req.body.projectPlatform)
    ? req.body.projectPlatform
    : req.body.projectPlatform
      ? [req.body.projectPlatform]
      : [];
  const descriptions = Array.isArray(req.body.projectDescription)
    ? req.body.projectDescription
    : req.body.projectDescription
      ? [req.body.projectDescription]
      : [];

  const maxLen = Math.max(titles.length, platforms.length, descriptions.length);
  const out = [];
  for (let i = 0; i < maxLen; i += 1) {
    const title = String(titles[i] || "").trim();
    const platform = String(platforms[i] || "").trim();
    const description = String(descriptions[i] || "").trim();
    if (!title && !platform && !description) continue;
    out.push({ title, platform, description });
  }
  if (out.length > 0) return out;

  return parsePipeRows(req.body.projects, 3).map(
    ([title, platform, description]) => ({
      title,
      platform,
      description
    })
  );
}

function isFilled(value) {
  return String(value || "").trim().length > 0;
}

function filterCompleteAboutCards(items) {
  return (items || []).filter(
    (item) => isFilled(item.title) && isFilled(item.description)
  );
}

function filterCompleteProjects(items) {
  return (items || []).filter(
    (item) =>
      isFilled(item.title) &&
      isFilled(item.platform) &&
      isFilled(item.description)
  );
}

function filterCompleteExperiences(items) {
  return (items || []).filter(
    (item) =>
      isFilled(item.period) &&
      isFilled(item.title) &&
      isFilled(item.description)
  );
}

function parseExperienceEntries(req) {
  const periods = Array.isArray(req.body.experiencePeriod)
    ? req.body.experiencePeriod
    : req.body.experiencePeriod
      ? [req.body.experiencePeriod]
      : [];
  const titles = Array.isArray(req.body.experienceTitle)
    ? req.body.experienceTitle
    : req.body.experienceTitle
      ? [req.body.experienceTitle]
      : [];
  const descriptions = Array.isArray(req.body.experienceDescription)
    ? req.body.experienceDescription
    : req.body.experienceDescription
      ? [req.body.experienceDescription]
      : [];

  const maxLen = Math.max(periods.length, titles.length, descriptions.length);
  const out = [];

  for (let i = 0; i < maxLen; i += 1) {
    const period = String(periods[i] || "").trim();
    const title = String(titles[i] || "").trim();
    const description = String(descriptions[i] || "").trim();
    if (!period && !title && !description) continue;
    out.push({ period, title, description });
  }

  if (out.length > 0) return out;

  // Backward compatibility for old textarea format.
  return parsePipeRows(req.body.experiences, 3).map(
    ([period, title, description]) => ({
      period,
      title,
      description
    })
  );
}

function slugifyName(value) {
  return (value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

/** Paths registered before `GET /:slug` — slugs must not collide. */
const RESERVED_SINGLE_SEGMENT_SLUGS = new Set(["out", "vcard"]);

function uniqueSlugFromName(fullName, portfolios) {
  const base = slugifyName(fullName) || `portfolio-${nanoid()}`;
  let slug = base;
  let counter = 2;

  while (
    RESERVED_SINGLE_SEGMENT_SLUGS.has(slug) ||
    portfolios.some((item) => item.slug === slug)
  ) {
    slug = `${base}-${counter}`;
    counter += 1;
  }

  return slug;
}

function toPipeRows(items, fields) {
  return (items || [])
    .map((item) => fields.map((field) => item[field] || "").join(" | "))
    .join("\n");
}

function normalizeTheme(value) {
  return value === "light" ? "light" : "dark";
}

function normalizeStyleTheme(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "anime-manga") return "glow";
  const allowed = new Set(["liquid-glass", "glow"]);
  return allowed.has(normalized) ? normalized : "liquid-glass";
}

function normalizeLayout(value) {
  const allowed = new Set(["default", "hero-reverse", "projects-first"]);
  return allowed.has(value) ? value : "default";
}

const THEME_COLOR_PRESETS = {
  dark: {
    colorBg: "#05070d",
    colorText: "#f5f8ff",
    colorAccent: "#88b3ff",
    colorCard: "#151d30"
  },
  light: {
    colorBg: "#eef3ff",
    colorText: "#0f1a2f",
    colorAccent: "#356ed5",
    colorCard: "#ffffff"
  }
};

const FONT_GOOGLE_PARAMS = {
  inter: "Inter:wght@400;500;600;700;800",
  poppins: "Poppins:wght@400;500;600;700;800",
  roboto: "Roboto:wght@400;500;700",
  "playfair-display": "Playfair+Display:wght@400;500;600;700",
  "space-grotesk": "Space+Grotesk:wght@400;500;600;700"
};

const FONT_STACK_CSS = {
  inter: '"Inter", system-ui, sans-serif',
  poppins: '"Poppins", system-ui, sans-serif',
  roboto: '"Roboto", system-ui, sans-serif',
  "playfair-display": '"Playfair Display", Georgia, serif',
  "space-grotesk": '"Space Grotesk", system-ui, sans-serif'
};

const FONT_BASE_PX = {
  small: 15,
  medium: 16,
  large: 18
};

const SECTION_IDS = ["hero", "about", "projects", "experience"];

function normalizeHexColor(value) {
  if (typeof value !== "string") return null;
  let s = value.trim();
  if (!s.startsWith("#")) s = `#${s}`;
  if (!/^#[0-9A-Fa-f]{6}$/.test(s)) return null;
  return s.toLowerCase();
}

function normalizeSectionOrder(value) {
  let parts;
  if (Array.isArray(value)) {
    parts = value.map((p) => String(p).trim().toLowerCase()).filter(Boolean);
  } else if (typeof value === "string") {
    parts = value
      .split(",")
      .map((p) => p.trim().toLowerCase())
      .filter(Boolean);
  } else {
    parts = [];
  }

  const seen = new Set();
  const out = [];
  for (const p of parts) {
    if (SECTION_IDS.includes(p) && !seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  for (const id of SECTION_IDS) {
    if (!seen.has(id)) out.push(id);
  }
  return out;
}

function normalizeHeroLayout(value) {
  const allowed = new Set([
    "split",
    "split-reverse",
    "text-only",
    "card-only",
    "stacked"
  ]);
  return allowed.has(value) ? value : "split";
}

function normalizeAboutLayout(value) {
  const allowed = new Set(["grid-3", "grid-2", "scroll"]);
  return allowed.has(value) ? value : "grid-3";
}

function normalizeProjectsLayout(value) {
  const allowed = new Set(["cols-3", "cols-2", "list"]);
  return allowed.has(value) ? value : "cols-3";
}

function normalizeExperienceLayout(value) {
  const allowed = new Set(["timeline", "grid", "compact"]);
  return allowed.has(value) ? value : "timeline";
}

function normalizeFontFamily(value) {
  const allowed = new Set([
    "inter",
    "poppins",
    "roboto",
    "playfair-display",
    "space-grotesk"
  ]);
  return allowed.has(value) ? value : "inter";
}

function normalizeFontScale(value) {
  const allowed = new Set(["small", "medium", "large"]);
  return allowed.has(value) ? value : "medium";
}

function normalizeShowNavFooter(value, defaultTrue = true) {
  if (value === "0" || value === 0 || value === false) return false;
  if (value === "1" || value === 1 || value === true) return true;
  return defaultTrue;
}

function normalizeImageUrl(value) {
  const raw = (value || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) return raw;
  if (/^\/asset\/[a-zA-Z0-9_-]+$/.test(raw)) return raw;
  if (/^\/uploads\/[a-zA-Z0-9._-]+$/.test(raw)) return raw;
  return "";
}

function normalizePlanKey(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (raw === "basic") return "free";
  if (raw === "free" || raw === "plus" || raw === "pro") return raw;
  return "free";
}

function getPlanMeta(planKey) {
  return PLAN_DEFINITIONS[normalizePlanKey(planKey)] || PLAN_DEFINITIONS.free;
}

function getPlanRank(planKey) {
  const normalized = normalizePlanKey(planKey);
  if (normalized === "pro") return 3;
  if (normalized === "plus") return 2;
  return 1;
}

function isPaidPlanKey(planKey) {
  const normalized = normalizePlanKey(planKey);
  return normalized === "plus" || normalized === "pro";
}

function resolveCurrentPlan(user) {
  if (!user) return "free";
  const normalizedPlan = normalizePlanKey(user.plan);
  if (!isPaidPlanKey(normalizedPlan)) return "free";
  if (user.planStatus !== "active") return "free";
  if (!user.planExpiresAt) return "free";
  return new Date(user.planExpiresAt).getTime() > Date.now() ? normalizedPlan : "free";
}

function canCustomizePortfolio(user) {
  const plan = resolveCurrentPlan(user);
  return plan === "plus" || plan === "pro";
}

function canUseWebsiteBuilder(user) {
  return resolveCurrentPlan(user) === "pro";
}

function getPlanLabel(user) {
  const plan = resolveCurrentPlan(user);
  return `${getPlanMeta(plan).label} Plan`;
}

function normalizeBuilderText(value, maxLen = 4000) {
  const str = String(value || "").trim();
  if (!str) return "";
  return str.slice(0, maxLen);
}

function normalizeBuilderBlockType(value) {
  const allowed = new Set([
    "hero",
    "text",
    "paragraph",
    "button",
    "link",
    "image",
    "glass-card",
    "social"
  ]);
  const normalized = String(value || "").trim().toLowerCase();
  return allowed.has(normalized) ? normalized : "text";
}

function normalizeBuilderElementType(value) {
  const allowed = new Set(["heading", "paragraph", "button", "link", "image", "glass-card"]);
  const normalized = String(value || "").trim().toLowerCase();
  return allowed.has(normalized) ? normalized : "paragraph";
}

function normalizeBuilderElements(value) {
  if (!Array.isArray(value)) return [];
  const elements = [];

  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const xRaw = Number(item.x);
    const yRaw = Number(item.y);
    const widthRaw = Number(item.width);
    const heightRaw = Number(item.height);
    const element = {
      id: normalizeBuilderText(item.id, 40) || nanoid(),
      type: normalizeBuilderElementType(item.type),
      text: normalizeBuilderText(item.text, 3000),
      href: "",
      imageUrl: normalizeImageUrl(item.imageUrl),
      textColor: normalizeHexColor(item.textColor) || "",
      bgColor: normalizeHexColor(item.bgColor) || "",
      align: String(item.align || "").trim().toLowerCase() === "center" ? "center" : "left",
      x: Number.isFinite(xRaw) ? Math.max(0, Math.min(5000, Math.round(xRaw))) : 40,
      y: Number.isFinite(yRaw) ? Math.max(0, Math.min(5000, Math.round(yRaw))) : 40,
      width: Number.isFinite(widthRaw) ? Math.max(120, Math.min(1600, Math.round(widthRaw))) : 320,
      height: Number.isFinite(heightRaw) ? Math.max(40, Math.min(1200, Math.round(heightRaw))) : 120
    };
    const maybeHref = normalizeBuilderText(item.href, 900);
    if (!maybeHref || isSafeOutboundTarget(maybeHref)) {
      element.href = maybeHref;
    }
    elements.push(element);
  }

  return elements.slice(0, 60);
}

function normalizeBuilderSectionType(value) {
  const allowed = new Set(["blank", "hero", "about", "features", "contact"]);
  const normalized = String(value || "").trim().toLowerCase();
  return allowed.has(normalized) ? normalized : "blank";
}

function normalizeBuilderSections(value) {
  if (!Array.isArray(value)) return [];
  const sections = [];

  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const section = {
      id: normalizeBuilderText(item.id, 40) || nanoid(),
      name: normalizeBuilderText(item.name, 80) || "Section",
      type: normalizeBuilderSectionType(item.type),
      layout: String(item.layout || "").trim().toLowerCase() === "two-col" ? "two-col" : "single",
      bgColor: normalizeHexColor(item.bgColor) || "",
      elements: normalizeBuilderElements(item.elements)
    };
    sections.push(section);
  }

  return sections.slice(0, 30);
}

function normalizeBuilderSettings(value) {
  const src = value && typeof value === "object" ? value : {};
  const bgModeRaw = String(src.backgroundMode || "").trim().toLowerCase();
  const backgroundMode = bgModeRaw === "image" ? "image" : "color";
  const backgroundColor = normalizeHexColor(src.backgroundColor) || "#05070d";
  const textColor = normalizeHexColor(src.textColor) || "#f5f8ff";
  const accentColor = normalizeHexColor(src.accentColor) || "#88b3ff";
  const backgroundImageUrl = normalizeImageUrl(src.backgroundImageUrl);

  return {
    backgroundMode,
    backgroundColor,
    textColor,
    accentColor,
    backgroundImageUrl
  };
}

function normalizeBuilderHtmlSnapshot(value) {
  if (typeof value !== "string") return "";
  const raw = value.trim();
  if (!raw) return "";
  return raw.slice(0, 800000);
}

function normalizeBuilderConfig(value) {
  const src = value && typeof value === "object" ? value : {};
  const legacyBlocks = Array.isArray(src.blocks) ? src.blocks : [];
  let sections = normalizeBuilderSections(src.sections);
  if (sections.length === 0 && legacyBlocks.length > 0) {
    // Legacy migration: convert old flat blocks to a single section.
    sections = [
      {
        id: nanoid(),
        name: "Main section",
        type: "blank",
        layout: "single",
        bgColor: "",
        elements: legacyBlocks.map((block) => ({
          id: normalizeBuilderText(block.id, 40) || nanoid(),
          type:
            block.type === "hero"
              ? "heading"
              : block.type === "image"
                ? "image"
                : block.type === "button" || block.type === "cta" || block.type === "link"
                  ? "button"
                  : block.type === "glass-card"
                    ? "glass-card"
                    : "paragraph",
          text:
            normalizeBuilderText(block.title, 200) ||
            normalizeBuilderText(block.body, 2000),
          href: normalizeBuilderText(block.buttonUrl, 900),
          imageUrl: normalizeImageUrl(block.imageUrl),
          textColor: "",
          bgColor: "",
          align: "left"
        }))
      }
    ];
  }

  return {
    enabled: src.enabled === true,
    sections: normalizeBuilderSections(sections),
    settings: normalizeBuilderSettings(src.settings),
    htmlSnapshot: normalizeBuilderHtmlSnapshot(src.htmlSnapshot)
  };
}

function createAssetToken() {
  return crypto.randomBytes(18).toString("base64url");
}

function registerPrivateAssetForUser(user, uploadedFile, kind) {
  if (!user || !uploadedFile) return "";
  user.uploadedAssets ||= [];

  const token = createAssetToken();
  const assetRecord = {
    id: nanoid(),
    token,
    kind,
    storedName: uploadedFile.filename,
    originalName: uploadedFile.originalname || "",
    mimeType: uploadedFile.mimetype || "",
    size: uploadedFile.size || 0,
    createdAt: new Date().toISOString()
  };

  user.uploadedAssets.unshift(assetRecord);
  return `/asset/${token}`;
}

function applyUploadedImageUrlsToRequest(req, user) {
  const profileImageFile = req.uploadedFilesMeta?.profileImageFile || null;
  const companyLogoFile = req.uploadedFilesMeta?.companyLogoFile || null;

  req.uploadedImageUrls = {
    profileImageUrl: profileImageFile
      ? registerPrivateAssetForUser(user, profileImageFile, "profile")
      : "",
    companyLogoUrl: companyLogoFile
      ? registerPrivateAssetForUser(user, companyLogoFile, "company-logo")
      : ""
  };
}

function buildGoogleFontHref(fontKey) {
  const param = FONT_GOOGLE_PARAMS[fontKey] || FONT_GOOGLE_PARAMS.inter;
  return `https://fonts.googleapis.com/css2?family=${param}&display=swap`;
}

function deriveLayoutVariant(sectionOrder, heroLayout) {
  const orderKey = sectionOrder.join(",");
  if (orderKey === "hero,projects,about,experience") return "projects-first";
  if (heroLayout === "split-reverse") return "hero-reverse";
  return "default";
}

function isSafeOutboundTarget(raw) {
  const s = String(raw || "").trim();
  if (!s) return false;
  if (/^mailto:/i.test(s)) {
    return /^mailto:[^<>"\s]+$/i.test(s);
  }
  try {
    const parsed = new URL(s);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function signOutboundLink(slug, targetUrl) {
  return crypto
    .createHmac("sha256", TRACKING_SECRET)
    .update(`${slug}\n${targetUrl}`)
    .digest("hex");
}

function buildTrackedOutboundHref(slug, targetUrl) {
  const sig = signOutboundLink(slug, targetUrl);
  return `/out?slug=${encodeURIComponent(slug)}&u=${encodeURIComponent(
    targetUrl
  )}&sig=${sig}`;
}

function resolvePortfolioForView(record) {
  const theme = normalizeTheme(record.theme);
  const styleTheme = normalizeStyleTheme(record.styleTheme);
  const preset = THEME_COLOR_PRESETS[theme];

  const missingSectionOrder =
    record.sectionOrder === undefined ||
    record.sectionOrder === null ||
    (typeof record.sectionOrder === "string" && !record.sectionOrder.trim()) ||
    (Array.isArray(record.sectionOrder) && record.sectionOrder.length === 0);

  const sectionOrder = missingSectionOrder
    ? record.layoutVariant === "projects-first"
      ? ["hero", "projects", "about", "experience"]
      : ["hero", "about", "projects", "experience"]
    : normalizeSectionOrder(record.sectionOrder);

  const heroLayout = record.heroLayout
    ? normalizeHeroLayout(record.heroLayout)
    : record.layoutVariant === "hero-reverse"
      ? "split-reverse"
      : "split";

  const fontFamily = normalizeFontFamily(record.fontFamily);
  const fontScale = normalizeFontScale(record.fontScale);
  const derivedVariant = deriveLayoutVariant(sectionOrder, heroLayout);
  const aboutCards = filterCompleteAboutCards(record.aboutCards);
  const projects = filterCompleteProjects(record.projects);
  const experiences = filterCompleteExperiences(record.experiences);
  const hasExperience = experiences.length > 0;

  return {
    ...record,
    theme,
    styleTheme,
    layoutVariant: derivedVariant,
    sectionOrder,
    hasExperience,
    aboutCards,
    projects,
    experiences,
    heroLayout,
    aboutLayout: normalizeAboutLayout(record.aboutLayout),
    projectsLayout: normalizeProjectsLayout(record.projectsLayout),
    experienceLayout: normalizeExperienceLayout(record.experienceLayout),
    showNavbar: normalizeShowNavFooter(record.showNavbar, true),
    showFooterContact: normalizeShowNavFooter(record.showFooterContact, true),
    fontFamily,
    fontScale,
    colorBg: normalizeHexColor(record.colorBg) || preset.colorBg,
    colorText: normalizeHexColor(record.colorText) || preset.colorText,
    colorAccent: normalizeHexColor(record.colorAccent) || preset.colorAccent,
    colorCard: normalizeHexColor(record.colorCard) || preset.colorCard,
    profileImageUrl: normalizeImageUrl(record.profileImageUrl),
    companyLogoUrl: normalizeImageUrl(record.companyLogoUrl),
    googleFontHref: buildGoogleFontHref(fontFamily),
    fontFamilyCss: FONT_STACK_CSS[fontFamily] || FONT_STACK_CSS.inter,
    fontBasePx: FONT_BASE_PX[fontScale] ?? 16
  };
}

function sanitizeNext(value) {
  if (typeof value !== "string") return "/dashboard";
  if (!value.startsWith("/")) return "/dashboard";
  return value;
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

function buildPortfolioPayload(req) {
  const theme = normalizeTheme(req.body.theme);
  const styleTheme = normalizeStyleTheme(req.body.styleTheme);
  const preset = THEME_COLOR_PRESETS[theme];
  const legacyLayout = normalizeLayout(req.body.layoutVariant);

  let sectionOrder;
  if (
    req.body.sectionOrder === undefined ||
    req.body.sectionOrder === null ||
    (typeof req.body.sectionOrder === "string" && !req.body.sectionOrder.trim())
  ) {
    sectionOrder =
      legacyLayout === "projects-first"
        ? ["hero", "projects", "about", "experience"]
        : ["hero", "about", "projects", "experience"];
  } else {
    sectionOrder = normalizeSectionOrder(req.body.sectionOrder);
  }

  const heroLayout = req.body.heroLayout
    ? normalizeHeroLayout(req.body.heroLayout)
    : legacyLayout === "hero-reverse"
      ? "split-reverse"
      : "split";

  const layoutVariant = deriveLayoutVariant(sectionOrder, heroLayout);

  return {
    fullName: (req.body.fullName || "Your Name").trim(),
    role: req.body.role || "Developer at Apple",
    headline: req.body.headline || "Crafting elegant software that feels magical.",
    heroText:
      req.body.heroText ||
      "I design and engineer high-performance product experiences with a strong focus on motion, clarity, and user delight.",
    shippingTitle: (req.body.shippingTitle || "").trim(),
    shippingHeading: (req.body.shippingHeading || "").trim(),
    shippingDescription: (req.body.shippingDescription || "").trim(),
    shippingPoints: splitLines(req.body.shippingPoints),
    aboutCards: filterCompleteAboutCards(parseAboutEntries(req)),
    projects: filterCompleteProjects(parseProjectEntries(req)),
    experiences: filterCompleteExperiences(parseExperienceEntries(req)),
    email: (req.body.email || "").trim(),
    linkedin: (req.body.linkedin || "").trim(),
    youtube: (req.body.youtube || "").trim(),
    instagram: (req.body.instagram || "").trim(),
    twitter: (req.body.twitter || "").trim(),
    github: (req.body.github || "").trim(),
    theme,
    styleTheme,
    layoutVariant,
    sectionOrder,
    heroLayout,
    profileImageUrl:
      req.uploadedImageUrls?.profileImageUrl ||
      normalizeImageUrl(req.body.profileImageUrl),
    companyLogoUrl:
      req.uploadedImageUrls?.companyLogoUrl ||
      normalizeImageUrl(req.body.companyLogoUrl),
    aboutLayout: normalizeAboutLayout(req.body.aboutLayout),
    projectsLayout: normalizeProjectsLayout(req.body.projectsLayout),
    experienceLayout: normalizeExperienceLayout(req.body.experienceLayout),
    showNavbar: normalizeShowNavFooter(req.body.showNavbar, true),
    showFooterContact: normalizeShowNavFooter(req.body.showFooterContact, true),
    fontFamily: normalizeFontFamily(req.body.fontFamily),
    fontScale: normalizeFontScale(req.body.fontScale),
    colorBg: normalizeHexColor(req.body.colorBg) || preset.colorBg,
    colorText: normalizeHexColor(req.body.colorText) || preset.colorText,
    colorAccent: normalizeHexColor(req.body.colorAccent) || preset.colorAccent,
    colorCard: normalizeHexColor(req.body.colorCard) || preset.colorCard
  };
}

const ANALYTICS_EVENT_LIMIT = 2500;
const ANALYTICS_ENGAGEMENT_EVENT_LIMIT_MS = 2 * 60 * 1000;

function parseCookieHeader(req) {
  const raw = String(req.headers.cookie || "");
  if (!raw) return {};

  const out = {};
  const parts = raw.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = value;
  }
  return out;
}

function sanitizeAnalyticsId(raw, maxLen = 80) {
  const value = String(raw || "").trim();
  if (!value) return "";
  const safe = value.replace(/[^a-zA-Z0-9_-]/g, "");
  if (!safe) return "";
  return safe.slice(0, maxLen);
}

function resolveClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").trim();
  if (forwarded) {
    const first = forwarded.split(",")[0].trim();
    if (first) return first;
  }
  return String(req.socket?.remoteAddress || req.ip || "").trim();
}

function createFallbackVisitorId(req) {
  const ua = String(req.get("user-agent") || "");
  const ip = resolveClientIp(req);
  return crypto
    .createHash("sha256")
    .update(`${ip}|${ua}|${TRACKING_SECRET}`)
    .digest("hex")
    .slice(0, 24);
}

function getOrCreateVisitorId(req, res) {
  const cookies = parseCookieHeader(req);
  const existing = sanitizeAnalyticsId(cookies.ll_vid, 64);
  if (existing) return existing;

  const generated = sanitizeAnalyticsId(`v_${nanoid()}${Date.now().toString(36)}`, 64);
  res.cookie("ll_vid", generated, {
    maxAge: 1000 * 60 * 60 * 24 * 365,
    httpOnly: false,
    sameSite: "lax"
  });
  return generated || createFallbackVisitorId(req);
}

function normalizePercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (n > 100) return 100;
  return Math.round(n * 100) / 100;
}

function normalizeCounterValue(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function normalizeCounterObject(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;

  for (const [rawKey, rawValue] of Object.entries(value)) {
    const key = String(rawKey || "").trim();
    if (!key) continue;
    const count = normalizeCounterValue(rawValue);
    if (count > 0) {
      out[key] = count;
    }
  }

  return out;
}

function normalizeDailyObject(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;

  for (const [rawDay, rawBucket] of Object.entries(value)) {
    const day = String(rawDay || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    const safeBucket =
      rawBucket && typeof rawBucket === "object" ? rawBucket : {};
    const views = normalizeCounterValue(safeBucket.views);
    const linkClicks = normalizeCounterValue(safeBucket.linkClicks);
    if (views > 0 || linkClicks > 0) {
      out[day] = { views, linkClicks };
    }
  }

  return out;
}

function normalizeHourlyObject(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;

  for (const [rawHour, rawCount] of Object.entries(value)) {
    const hour = Number(rawHour);
    if (!Number.isInteger(hour) || hour < 0 || hour > 23) continue;
    const count = normalizeCounterValue(rawCount);
    if (count > 0) {
      out[String(hour)] = count;
    }
  }

  return out;
}

function normalizeAnalyticsEvents(value) {
  if (!Array.isArray(value)) return [];

  const events = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;

    let type = "view";
    if (item.type === "link_click") type = "link_click";
    if (item.type === "engagement") type = "engagement";
    const at =
      typeof item.at === "string" && !Number.isNaN(Date.parse(item.at))
        ? item.at
        : "";
    if (!at) continue;

    events.push({
      type,
      at,
      day:
        typeof item.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(item.day)
          ? item.day
          : at.slice(0, 10),
      hour:
        Number.isInteger(item.hour) && item.hour >= 0 && item.hour <= 23
          ? item.hour
          : new Date(at).getHours(),
      referrer:
        typeof item.referrer === "string" && item.referrer.trim()
          ? item.referrer.trim()
          : "Direct",
      device:
        typeof item.device === "string" && item.device.trim()
          ? item.device.trim()
          : "Unknown",
      browser:
        typeof item.browser === "string" && item.browser.trim()
          ? item.browser.trim()
          : "Unknown",
      os:
        typeof item.os === "string" && item.os.trim() ? item.os.trim() : "Unknown",
      target:
        typeof item.target === "string" && item.target.trim()
          ? item.target.trim()
          : "",
      visitorId: sanitizeAnalyticsId(item.visitorId, 64),
      sessionId: sanitizeAnalyticsId(item.sessionId, 64),
      utmSource:
        typeof item.utmSource === "string" && item.utmSource.trim()
          ? item.utmSource.trim().slice(0, 80)
          : "",
      utmMedium:
        typeof item.utmMedium === "string" && item.utmMedium.trim()
          ? item.utmMedium.trim().slice(0, 80)
          : "",
      utmCampaign:
        typeof item.utmCampaign === "string" && item.utmCampaign.trim()
          ? item.utmCampaign.trim().slice(0, 100)
          : "",
      engagedMs: normalizeCounterValue(item.engagedMs),
      scrollDepth: normalizePercent(item.scrollDepth)
    });
  }

  events.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
  return events.slice(0, ANALYTICS_EVENT_LIMIT);
}

function normalizeAnalyticsRecord(value) {
  const source = value && typeof value === "object" ? value : {};
  const parsedLastSeenAt =
    typeof source.lastSeenAt === "string" && !Number.isNaN(Date.parse(source.lastSeenAt))
      ? source.lastSeenAt
      : "";

  return {
    views: normalizeCounterValue(source.views),
    linkClicks: normalizeCounterValue(source.linkClicks),
    daily: normalizeDailyObject(source.daily),
    referrers: normalizeCounterObject(source.referrers),
    devices: normalizeCounterObject(source.devices),
    browsers: normalizeCounterObject(source.browsers),
    operatingSystems: normalizeCounterObject(source.operatingSystems),
    links: normalizeCounterObject(source.links),
    utmSources: normalizeCounterObject(source.utmSources),
    utmMediums: normalizeCounterObject(source.utmMediums),
    utmCampaigns: normalizeCounterObject(source.utmCampaigns),
    hourly: normalizeHourlyObject(source.hourly),
    events: normalizeAnalyticsEvents(source.events),
    totalEngagedMs: normalizeCounterValue(source.totalEngagedMs),
    maxScrollDepth: normalizePercent(source.maxScrollDepth),
    lastSeenAt: parsedLastSeenAt
  };
}

function getDayKey(date) {
  return date.toISOString().slice(0, 10);
}

function incrementCounter(counterObj, key, amount = 1) {
  if (!key) return;
  const safeAmount = normalizeCounterValue(amount);
  if (!safeAmount) return;
  counterObj[key] = normalizeCounterValue(counterObj[key]) + safeAmount;
}

function getDeviceType(userAgentRaw) {
  const ua = String(userAgentRaw || "").toLowerCase();
  if (!ua) return "Unknown";
  if (/tablet|ipad/.test(ua)) return "Tablet";
  if (/mobi|iphone|android/.test(ua)) return "Mobile";
  return "Desktop";
}

function getBrowserName(userAgentRaw) {
  const ua = String(userAgentRaw || "").toLowerCase();
  if (!ua) return "Unknown";
  if (ua.includes("edg/")) return "Edge";
  if (ua.includes("opr/") || ua.includes("opera")) return "Opera";
  if (ua.includes("chrome/")) return "Chrome";
  if (ua.includes("firefox/")) return "Firefox";
  if (ua.includes("safari/") && !ua.includes("chrome/")) return "Safari";
  return "Other";
}

function getOperatingSystemName(userAgentRaw) {
  const ua = String(userAgentRaw || "").toLowerCase();
  if (!ua) return "Unknown";
  if (ua.includes("windows")) return "Windows";
  if (ua.includes("android")) return "Android";
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) return "iOS";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "macOS";
  if (ua.includes("linux")) return "Linux";
  return "Other";
}

function isLikelyBotUserAgent(userAgentRaw) {
  const ua = String(userAgentRaw || "").toLowerCase();
  if (!ua) return false;
  return /(bot|spider|crawler|preview|slurp|headless|lighthouse|facebookexternalhit)/.test(
    ua
  );
}

function getReferrerSource(req, slug) {
  const ref = String(req.get("referer") || req.get("referrer") || "").trim();
  if (!ref) return "Direct";

  try {
    const parsedRef = new URL(ref);
    const refHost = String(parsedRef.hostname || "").toLowerCase();
    const requestHost = String(req.get("host") || "")
      .split(":")[0]
      .toLowerCase();

    if (!refHost) return "Direct";
    if (requestHost && refHost === requestHost) {
      if (slug && parsedRef.pathname === `/${slug}`) {
        return "Internal Portfolio";
      }
      return "Internal";
    }

    return refHost.startsWith("www.") ? refHost.slice(4) : refHost;
  } catch {
    return "Unknown";
  }
}

function getTargetLabel(targetUrl) {
  if (!targetUrl) return "";
  if (/^mailto:/i.test(targetUrl)) return "Email";
  try {
    const parsed = new URL(targetUrl);
    const host = String(parsed.hostname || "").toLowerCase();
    if (!host) return "Other";
    return host.startsWith("www.") ? host.slice(4) : host;
  } catch {
    return "Other";
  }
}

function trackPortfolioAnalyticsEvent(portfolio, req, options) {
  const config = options || {};
  let eventType = "view";
  if (config.type === "link_click") eventType = "link_click";
  if (config.type === "engagement") eventType = "engagement";

  applyPortfolioDefaults(portfolio);
  const analytics = portfolio.analytics;

  const now = new Date();
  const atIso = now.toISOString();
  const dayKey = getDayKey(now);
  const hourKey = String(now.getHours());
  const ua = req.get("user-agent") || "";
  const sourceReferrer = getReferrerSource(req, portfolio.slug);
  const device = getDeviceType(ua);
  const browser = getBrowserName(ua);
  const os = getOperatingSystemName(ua);
  const visitorId =
    sanitizeAnalyticsId(config.visitorId, 64) || createFallbackVisitorId(req);
  const sessionId = sanitizeAnalyticsId(config.sessionId, 64);
  const utmSource = String(req.query.utm_source || "").trim().slice(0, 80);
  const utmMedium = String(req.query.utm_medium || "").trim().slice(0, 80);
  const utmCampaign = String(req.query.utm_campaign || "").trim().slice(0, 100);
  const engagedMs = Math.min(
    normalizeCounterValue(config.engagedMs),
    ANALYTICS_ENGAGEMENT_EVENT_LIMIT_MS
  );
  const scrollDepth = normalizePercent(config.scrollDepth);
  const targetLabel =
    eventType === "link_click" ? getTargetLabel(config.targetUrl || "") : "";

  if (eventType === "view") {
    analytics.views += 1;
  } else if (eventType === "link_click") {
    analytics.linkClicks += 1;
  }

  if (!analytics.daily[dayKey]) {
    analytics.daily[dayKey] = { views: 0, linkClicks: 0 };
  }
  if (eventType === "link_click") {
    analytics.daily[dayKey].linkClicks += 1;
  } else if (eventType === "view") {
    analytics.daily[dayKey].views += 1;
  }

  incrementCounter(analytics.hourly, hourKey);
  incrementCounter(analytics.referrers, sourceReferrer);
  incrementCounter(analytics.devices, device);
  incrementCounter(analytics.browsers, browser);
  incrementCounter(analytics.operatingSystems, os);

  if (utmSource) incrementCounter(analytics.utmSources, utmSource);
  if (utmMedium) incrementCounter(analytics.utmMediums, utmMedium);
  if (utmCampaign) incrementCounter(analytics.utmCampaigns, utmCampaign);

  if (eventType === "engagement" && engagedMs > 0) {
    analytics.totalEngagedMs += engagedMs;
  }
  if (scrollDepth > analytics.maxScrollDepth) {
    analytics.maxScrollDepth = scrollDepth;
  }
  if (eventType === "link_click" && targetLabel) {
    incrementCounter(analytics.links, targetLabel);
  }

  analytics.events.unshift({
    type: eventType,
    at: atIso,
    day: dayKey,
    hour: Number(hourKey),
    referrer: sourceReferrer,
    device,
    browser,
    os,
    target: targetLabel,
    visitorId,
    sessionId,
    utmSource,
    utmMedium,
    utmCampaign,
    engagedMs,
    scrollDepth
  });
  if (analytics.events.length > ANALYTICS_EVENT_LIMIT) {
    analytics.events = analytics.events.slice(0, ANALYTICS_EVENT_LIMIT);
  }

  analytics.lastSeenAt = atIso;
}

function getRecentDayKeys(days) {
  const out = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i -= 1) {
    const date = new Date(now);
    date.setDate(now.getDate() - i);
    out.push(getDayKey(date));
  }
  return out;
}

function getTopEntries(counterObj, limit = 8) {
  return Object.entries(counterObj || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));
}

function mergeCounterObjects(target, source) {
  for (const [key, value] of Object.entries(source || {})) {
    incrementCounter(target, key, value);
  }
}

function buildAnalyticsViewModel(portfolios) {
  const totals = { views: 0, linkClicks: 0 };
  const aggregateDaily = {};
  const aggregateReferrers = {};
  const aggregateDevices = {};
  const aggregateBrowsers = {};
  const aggregateOperatingSystems = {};
  const aggregateLinks = {};
  const aggregateUtmSources = {};
  const aggregateUtmCampaigns = {};
  const aggregateHourly = {};
  const portfolioRows = [];
  const recentEvents = [];
  const sessionStats = new Map();
  const visitorsThirtyDays = new Set();
  const visitorSessionCount = new Map();
  const nowMs = Date.now();
  const thirtyDaysAgoMs = nowMs - 30 * 24 * 60 * 60 * 1000;

  for (const portfolio of portfolios) {
    applyPortfolioDefaults(portfolio);
    const analytics = portfolio.analytics;

    totals.views += analytics.views;
    totals.linkClicks += analytics.linkClicks;

    mergeCounterObjects(aggregateReferrers, analytics.referrers);
    mergeCounterObjects(aggregateDevices, analytics.devices);
    mergeCounterObjects(aggregateBrowsers, analytics.browsers);
    mergeCounterObjects(aggregateOperatingSystems, analytics.operatingSystems);
    mergeCounterObjects(aggregateLinks, analytics.links);
    mergeCounterObjects(aggregateUtmSources, analytics.utmSources);
    mergeCounterObjects(aggregateUtmCampaigns, analytics.utmCampaigns);
    mergeCounterObjects(aggregateHourly, analytics.hourly);

    for (const [day, bucket] of Object.entries(analytics.daily)) {
      if (!aggregateDaily[day]) {
        aggregateDaily[day] = { views: 0, linkClicks: 0 };
      }
      aggregateDaily[day].views += normalizeCounterValue(bucket.views);
      aggregateDaily[day].linkClicks += normalizeCounterValue(bucket.linkClicks);
    }

    const views = analytics.views;
    const linkClicks = analytics.linkClicks;
    const ctr = views > 0 ? (linkClicks / views) * 100 : 0;

    portfolioRows.push({
      fullName: portfolio.fullName || "Untitled Portfolio",
      slug: portfolio.slug || "",
      views,
      linkClicks,
      ctr,
      lastSeenAt: analytics.lastSeenAt || ""
    });

    for (const event of analytics.events) {
      const eventAtMs = new Date(event.at).getTime();
      if (!Number.isFinite(eventAtMs)) continue;

      const visitorId = sanitizeAnalyticsId(event.visitorId, 64) || "unknown";
      const sessionId =
        sanitizeAnalyticsId(event.sessionId, 64) ||
        `${visitorId}-${event.day || "unknown"}`;
      const sessionKey = `${portfolio.slug || "na"}|${sessionId}`;

      if (!sessionStats.has(sessionKey)) {
        sessionStats.set(sessionKey, {
          views: 0,
          clicks: 0,
          engagedMs: 0,
          maxScrollDepth: 0,
          visitorId
        });
      }
      const stats = sessionStats.get(sessionKey);

      if (event.type === "view") stats.views += 1;
      if (event.type === "link_click") stats.clicks += 1;
      if (event.type === "engagement") {
        stats.engagedMs += normalizeCounterValue(event.engagedMs);
        stats.maxScrollDepth = Math.max(
          stats.maxScrollDepth,
          normalizePercent(event.scrollDepth)
        );
      }

      if (eventAtMs >= thirtyDaysAgoMs) {
        visitorsThirtyDays.add(visitorId);
      }

      recentEvents.push({
        ...event,
        portfolioName: portfolio.fullName || "Untitled Portfolio",
        portfolioSlug: portfolio.slug || "",
        sessionId
      });
    }
  }

  for (const value of sessionStats.values()) {
    const current = visitorSessionCount.get(value.visitorId) || 0;
    visitorSessionCount.set(value.visitorId, current + 1);
  }

  const totalSessions = sessionStats.size;
  let bounceSessions = 0;
  let sessionEngagedTotalMs = 0;
  let sessionScrollTotal = 0;
  let sessionWithScroll = 0;
  for (const item of sessionStats.values()) {
    const isBounce = item.views <= 1 && item.clicks === 0 && item.engagedMs < 15000;
    if (isBounce) bounceSessions += 1;
    sessionEngagedTotalMs += item.engagedMs;
    if (item.maxScrollDepth > 0) {
      sessionScrollTotal += item.maxScrollDepth;
      sessionWithScroll += 1;
    }
  }

  portfolioRows.sort((a, b) => b.views - a.views || b.linkClicks - a.linkClicks);
  recentEvents.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());

  const dailyKeys = getRecentDayKeys(30);
  const dailyViews = dailyKeys.map((day) => aggregateDaily[day]?.views || 0);
  const dailyClicks = dailyKeys.map((day) => aggregateDaily[day]?.linkClicks || 0);
  const hourlyLabels = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const hourlyData = Array.from({ length: 24 }, (_, i) => aggregateHourly[String(i)] || 0);

  const avgDailyViews = dailyViews.reduce((sum, value) => sum + value, 0) / dailyViews.length;
  const ctrTotal = totals.views > 0 ? (totals.linkClicks / totals.views) * 100 : 0;
  const uniqueVisitors30d = visitorsThirtyDays.size;
  const returningVisitors30d = Array.from(visitorSessionCount.values()).filter(
    (count) => count > 1
  ).length;
  const bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;
  const avgEngagementSec =
    totalSessions > 0 ? sessionEngagedTotalMs / totalSessions / 1000 : 0;
  const avgScrollDepth =
    sessionWithScroll > 0 ? sessionScrollTotal / sessionWithScroll : 0;

  return {
    summary: {
      views: totals.views,
      linkClicks: totals.linkClicks,
      ctrTotal,
      avgDailyViews,
      portfoliosTracked: portfolios.length,
      uniqueVisitors30d,
      returningVisitors30d,
      sessions: totalSessions,
      bounceRate,
      avgEngagementSec,
      avgScrollDepth
    },
    charts: {
      daily: {
        labels: dailyKeys,
        views: dailyViews,
        clicks: dailyClicks
      },
      hourly: {
        labels: hourlyLabels,
        events: hourlyData
      },
      portfolios: portfolioRows.slice(0, 10).map((row) => ({
        label: row.fullName,
        views: row.views,
        clicks: row.linkClicks
      })),
      referrers: getTopEntries(aggregateReferrers, 8),
      devices: getTopEntries(aggregateDevices, 6),
      browsers: getTopEntries(aggregateBrowsers, 6),
      operatingSystems: getTopEntries(aggregateOperatingSystems, 6),
      links: getTopEntries(aggregateLinks, 8),
      utmSources: getTopEntries(aggregateUtmSources, 8),
      utmCampaigns: getTopEntries(aggregateUtmCampaigns, 8)
    },
    portfolioRows,
    recentEvents: recentEvents.slice(0, 120)
  };
}

function applyPortfolioDefaults(record) {
  if (!Array.isArray(record.shippingPoints)) record.shippingPoints = [];
  if (!Array.isArray(record.aboutCards)) record.aboutCards = [];
  if (!Array.isArray(record.projects)) record.projects = [];
  if (!Array.isArray(record.experiences)) record.experiences = [];
  record.analytics = normalizeAnalyticsRecord(record.analytics);
}

async function loadDb() {
  await db.read();
  db.data ||= { portfolios: [], users: [], pendingSignups: [] };
  db.data.portfolios ||= [];
  db.data.users ||= [];
  db.data.pendingSignups ||= [];

  let needsWrite = false;

  const nowMs = Date.now();
  const pendingBefore = db.data.pendingSignups.length;
  db.data.pendingSignups = db.data.pendingSignups.filter(
    (p) => new Date(p.expiresAt).getTime() > nowMs
  );
  if (db.data.pendingSignups.length !== pendingBefore) {
    needsWrite = true;
  }

  db.data.portfolios.forEach((portfolio) => {
    if (!portfolio.portfolioId) {
      portfolio.portfolioId = nanoid();
      needsWrite = true;
    }

    if (!portfolio.ownerEmail && portfolio.creatorEmail) {
      portfolio.ownerEmail = portfolio.creatorEmail;
      needsWrite = true;
    }

    if ("businessTitle" in portfolio) {
      delete portfolio.businessTitle;
      needsWrite = true;
    }

    if ("businessDescription" in portfolio) {
      delete portfolio.businessDescription;
      needsWrite = true;
    }

    // Keep reserved paths dedicated for app/system routes.
    if (RESERVED_SINGLE_SEGMENT_SLUGS.has(String(portfolio.slug || "").trim())) {
      portfolio.slug = uniqueSlugFromName(
        portfolio.fullName || "Portfolio",
        db.data.portfolios
      );
      needsWrite = true;
    }

    const analyticsBefore = JSON.stringify(portfolio.analytics || null);
    portfolio.analytics = normalizeAnalyticsRecord(portfolio.analytics);
    if (analyticsBefore !== JSON.stringify(portfolio.analytics)) {
      needsWrite = true;
    }

    const builderBefore = JSON.stringify(portfolio.builder || null);
    portfolio.builder = normalizeBuilderConfig(portfolio.builder);
    if (builderBefore !== JSON.stringify(portfolio.builder)) {
      needsWrite = true;
    }
  });

  db.data.users.forEach((user) => {
    if (!user.plan) {
      user.plan = "free";
      needsWrite = true;
    }

    if (user.planSchemaVersion !== PLAN_SCHEMA_VERSION) {
      const legacyPlan = normalizePlanKey(user.plan);
      // Existing "pro" users map to Plus in the new 3-tier model.
      user.plan = legacyPlan === "pro" ? "plus" : legacyPlan;
      user.planSchemaVersion = PLAN_SCHEMA_VERSION;
      needsWrite = true;
    }

    const normalizedPlan = normalizePlanKey(user.plan);
    if (normalizedPlan !== user.plan) {
      user.plan = normalizedPlan;
      needsWrite = true;
    }

    if (!user.planStatus) {
      user.planStatus = isPaidPlanKey(user.plan) ? "active" : "inactive";
      needsWrite = true;
    }

    if (isPaidPlanKey(user.plan) && user.planExpiresAt) {
      const expired = new Date(user.planExpiresAt).getTime() <= Date.now();
      if (expired) {
        user.plan = "free";
        user.planStatus = "expired";
        user.planExpiresAt = null;
        needsWrite = true;
      }
    }

    if (!isPaidPlanKey(user.plan) && user.planStatus === "active") {
      user.planStatus = "inactive";
      needsWrite = true;
    }

    if (!Array.isArray(user.uploadedAssets)) {
      user.uploadedAssets = [];
      needsWrite = true;
    }
  });

  if (needsWrite) {
    await db.write();
  }
}

function getUserBySession(req) {
  if (!req.session.user) return null;
  return db.data.users.find((u) => u.id === req.session.user.id) || null;
}

function activatePaidPlan(user, planKey) {
  const normalizedPlan = normalizePlanKey(planKey);
  const planMeta = getPlanMeta(normalizedPlan);
  if (!isPaidPlanKey(normalizedPlan)) {
    return;
  }
  const now = new Date();
  const expiresAt = addDays(now, planMeta.durationDays);

  user.plan = normalizedPlan;
  user.planStatus = "active";
  user.planSchemaVersion = PLAN_SCHEMA_VERSION;
  user.planActivatedAt = now.toISOString();
  user.planExpiresAt = expiresAt.toISOString();
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

async function claimLegacyPortfoliosForUser(user) {
  await loadDb();

  let hasChanges = false;
  const normalizedUserName = (user.fullName || "").trim().toLowerCase();
  const normalizedUserEmail = (user.email || "").trim().toLowerCase();

  db.data.portfolios.forEach((item) => {
    const normalizedItemName = (item.fullName || "").trim().toLowerCase();
    const normalizedOwnerEmail = (item.ownerEmail || "").trim().toLowerCase();
    const normalizedCreatorEmail = (item.creatorEmail || "").trim().toLowerCase();
    const normalizedContactEmail = (item.email || "").trim().toLowerCase();

    const alreadyOwnedByAnotherUser =
      item.ownerUserId && item.ownerUserId !== user.id;

    if (alreadyOwnedByAnotherUser) return;

    const isLegacyMatch =
      !item.ownerUserId &&
      (
        normalizedOwnerEmail === normalizedUserEmail ||
        normalizedCreatorEmail === normalizedUserEmail ||
        normalizedContactEmail === normalizedUserEmail ||
        normalizedItemName === normalizedUserName
      );

    if (isLegacyMatch) {
      item.ownerUserId = user.id;
      item.ownerEmail = user.email;
      hasChanges = true;
    }
  });

  if (hasChanges) {
    await db.write();
  }
}

app.get("/", (req, res) => {
  res.render("landing");
});

app.get("/vcard", (_req, res) => {
  if (!VCARD_REDIRECT_URL) {
    return res
      .status(503)
      .send(
        "VCARD_REDIRECT_URL is not configured. Set it in your environment to your external digital visiting card URL."
      );
  }

  if (!isSafeOutboundTarget(VCARD_REDIRECT_URL)) {
    return res
      .status(500)
      .send("VCARD_REDIRECT_URL is invalid. Use an absolute http(s) URL.");
  }

  return res.redirect(302, VCARD_REDIRECT_URL);
});

app.get("/signup", (req, res) => {
  res.render("auth", { mode: "signup", error: "" });
});

app.get("/signup/cancel", (req, res) => {
  delete req.session.pendingSignupId;
  delete req.session.signupOtpDevHint;
  res.redirect("/signup");
});

app.get("/signup/verify", async (req, res) => {
  await loadDb();

  const pendingId = req.session.pendingSignupId;
  if (!pendingId) {
    return res.redirect("/signup");
  }

  const pending = db.data.pendingSignups.find((p) => p.id === pendingId);
  if (!pending) {
    delete req.session.pendingSignupId;
    delete req.session.signupOtpDevHint;
    return res.redirect("/signup");
  }

  if (new Date(pending.expiresAt).getTime() <= Date.now()) {
    db.data.pendingSignups = db.data.pendingSignups.filter(
      (p) => p.id !== pendingId
    );
    delete req.session.pendingSignupId;
    delete req.session.signupOtpDevHint;
    await db.write();
    return res.status(400).render("auth", {
      mode: "signup",
      error: "That code expired. Please sign up again to get a new one."
    });
  }

  const devHint = Boolean(req.session.signupOtpDevHint);
  delete req.session.signupOtpDevHint;

  return res.render("signup-verify", {
    error: "",
    info: devHint
      ? "SMTP is not configured on this server — your code was printed in the terminal running the app."
      : "",
    maskedEmail: maskEmail(pending.email)
  });
});

app.post("/signup", async (req, res) => {
  await loadDb();

  const fullName = (req.body.fullName || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!fullName || !email || !password) {
    return res.status(400).render("auth", {
      mode: "signup",
      error: "Please fill full name, email, and password."
    });
  }

  if (password.length < 6) {
    return res.status(400).render("auth", {
      mode: "signup",
      error: "Password must be at least 6 characters."
    });
  }

  const existingUser = db.data.users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(400).render("auth", {
      mode: "signup",
      error: "An account with this email already exists."
    });
  }

  db.data.pendingSignups = db.data.pendingSignups.filter(
    (p) => p.email !== email
  );

  const otp = String(crypto.randomInt(100000, 1000000));
  const otpHash = await bcrypt.hash(otp, OTP_BCRYPT_ROUNDS);
  const passwordHash = await bcrypt.hash(password, 10);
  const now = Date.now();
  const pending = {
    id: nanoid(),
    fullName,
    email,
    passwordHash,
    otpHash,
    expiresAt: new Date(now + OTP_TTL_MS).toISOString(),
    lastOtpSentAt: new Date(now).toISOString()
  };

  db.data.pendingSignups.unshift(pending);

  try {
    const sendResult = await sendSignupOtpEmail(email, otp, fullName);
    await db.write();
    req.session.pendingSignupId = pending.id;
    req.session.signupOtpDevHint = sendResult.dev === true;
    return res.redirect("/signup/verify");
  } catch (err) {
    console.error("sendSignupOtpEmail:", err);
    db.data.pendingSignups = db.data.pendingSignups.filter(
      (p) => p.id !== pending.id
    );
    await db.write();
    return res.status(500).render("auth", {
      mode: "signup",
      error:
        "We could not send the verification email. Check SMTP configuration and try again."
    });
  }
});

app.post("/signup/resend", async (req, res) => {
  await loadDb();

  const pendingId = req.session.pendingSignupId;
  if (!pendingId) {
    return res.redirect("/signup");
  }

  const pending = db.data.pendingSignups.find((p) => p.id === pendingId);
  if (!pending) {
    delete req.session.pendingSignupId;
    return res.redirect("/signup");
  }

  const now = Date.now();
  if (
    pending.lastOtpSentAt &&
    now - new Date(pending.lastOtpSentAt).getTime() < OTP_RESEND_COOLDOWN_MS
  ) {
    return res.render("signup-verify", {
      error: "",
      info: "Please wait about a minute before requesting another code.",
      maskedEmail: maskEmail(pending.email)
    });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  pending.otpHash = await bcrypt.hash(otp, OTP_BCRYPT_ROUNDS);
  pending.expiresAt = new Date(now + OTP_TTL_MS).toISOString();
  pending.lastOtpSentAt = new Date(now).toISOString();

  try {
    const sendResult = await sendSignupOtpEmail(
      pending.email,
      otp,
      pending.fullName
    );
    await db.write();
    const info =
      sendResult.dev === true
        ? "New code logged to the server console (SMTP not configured)."
        : "A new code has been sent to your email.";
    return res.render("signup-verify", {
      error: "",
      info,
      maskedEmail: maskEmail(pending.email)
    });
  } catch (err) {
    console.error("signup resend:", err);
    await db.write();
    return res.render("signup-verify", {
      error: "Could not send email. Try again shortly.",
      info: "",
      maskedEmail: maskEmail(pending.email)
    });
  }
});

app.post("/signup/verify", async (req, res) => {
  await loadDb();

  const pendingId = req.session.pendingSignupId;
  if (!pendingId) {
    return res.redirect("/signup");
  }

  const pending = db.data.pendingSignups.find((p) => p.id === pendingId);
  if (!pending) {
    delete req.session.pendingSignupId;
    return res.redirect("/signup");
  }

  if (new Date(pending.expiresAt).getTime() <= Date.now()) {
    db.data.pendingSignups = db.data.pendingSignups.filter(
      (p) => p.id !== pendingId
    );
    delete req.session.pendingSignupId;
    await db.write();
    return res.status(400).render("auth", {
      mode: "signup",
      error: "That code expired. Please sign up again."
    });
  }

  const rawOtp = (req.body.otp || "").toString().replace(/\D/g, "");
  if (!/^\d{6}$/.test(rawOtp)) {
    return res.status(400).render("signup-verify", {
      error: "Enter the 6-digit code from your email.",
      info: "",
      maskedEmail: maskEmail(pending.email)
    });
  }

  const ok = await bcrypt.compare(rawOtp, pending.otpHash);
  if (!ok) {
    return res.status(400).render("signup-verify", {
      error: "Invalid code. Try again or request a new one.",
      info: "",
      maskedEmail: maskEmail(pending.email)
    });
  }

  const user = {
    id: nanoid(),
    fullName: pending.fullName,
    email: pending.email,
    passwordHash: pending.passwordHash,
    createdAt: new Date().toISOString(),
    plan: "free",
    planStatus: "inactive",
    planExpiresAt: null,
    planSchemaVersion: PLAN_SCHEMA_VERSION
  };

  db.data.users.unshift(user);
  db.data.pendingSignups = db.data.pendingSignups.filter(
    (p) => p.id !== pendingId
  );
  await db.write();

  delete req.session.pendingSignupId;
  delete req.session.signupOtpDevHint;

  req.session.user = {
    id: user.id,
    fullName: user.fullName,
    email: user.email
  };

  await claimLegacyPortfoliosForUser(req.session.user);
  return res.redirect("/dashboard");
});

app.get("/login", (req, res) => {
  res.render("auth", { mode: "login", error: "" });
});

app.post("/login", async (req, res) => {
  await loadDb();

  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  const user = db.data.users.find((item) => item.email === email);

  if (!user) {
    return res.status(401).render("auth", {
      mode: "login",
      error: "No account found with this email."
    });
  }

  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    return res.status(401).render("auth", {
      mode: "login",
      error: "Incorrect password."
    });
  }

  req.session.user = {
    id: user.id,
    fullName: user.fullName,
    email: user.email
  };

  await claimLegacyPortfoliosForUser(req.session.user);
  return res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.post("/delete-account", requireAuth, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const userId = req.session.user.id;

  db.data.users = (db.data.users || []).filter((u) => u.id !== userId);
  db.data.portfolios = (db.data.portfolios || []).filter(
    (p) => p.ownerUserId !== userId
  );

  await db.write();

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const currentPlan = resolveCurrentPlan(user);
  const isPaidPlan = currentPlan !== "free";
  const isPro = currentPlan === "pro";

  const myPortfolios = db.data.portfolios.filter(
    (item) => item.ownerUserId === req.session.user.id
  );

  for (const p of myPortfolios) {
    applyPortfolioDefaults(p);
  }

  res.render("dashboard", {
    portfolios: myPortfolios,
    isPaidPlan,
    isPro,
    canCustomize: canCustomizePortfolio(user),
    canUseBuilder: canUseWebsiteBuilder(user),
    planLabel: getPlanLabel(user)
  });
});

app.get("/analytics", requireAuth, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const currentPlan = resolveCurrentPlan(user);
  const isPaidPlan = currentPlan !== "free";
  const isPro = currentPlan === "pro";
  const myPortfolios = db.data.portfolios.filter(
    (item) => item.ownerUserId === req.session.user.id
  );
  const analytics = buildAnalyticsViewModel(myPortfolios);

  return res.render("analytics", {
    isPaidPlan,
    isPro,
    planLabel: getPlanLabel(user),
    analytics
  });
});

app.get("/form.html", requireAuth, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const canCreateUnlimited = canCustomizePortfolio(user);

  const myPortfolioCount = db.data.portfolios.filter(
    (p) => p.ownerUserId === req.session.user.id
  ).length;

  if (!canCreateUnlimited && myPortfolioCount >= 1) {
    return res.redirect(
      `/pricing?reason=create&plan=plus&next=${encodeURIComponent("/form.html")}`
    );
  }

  return res.render("form");
});

app.post("/create", requireAuth, handlePortfolioImageUpload, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const canCreateUnlimited = canCustomizePortfolio(user);
  applyUploadedImageUrlsToRequest(req, user);

  const myPortfolioCount = db.data.portfolios.filter(
    (p) => p.ownerUserId === req.session.user.id
  ).length;

  if (!canCreateUnlimited && myPortfolioCount >= 1) {
    return res.redirect(
      `/pricing?reason=create&plan=plus&next=${encodeURIComponent("/form.html")}`
    );
  }

  const now = new Date().toISOString();
  const payload = buildPortfolioPayload(req);
  const slug = uniqueSlugFromName(payload.fullName, db.data.portfolios);

  const record = {
    id: slug,
    portfolioId: nanoid(),
    slug,
    ownerUserId: req.session.user.id,
    ownerEmail: req.session.user.email,
    creatorEmail: req.session.user.email,
    createdAt: now,
    ...payload
  };

  applyPortfolioDefaults(record);

  db.data.portfolios.unshift(record);
  await db.write();

  return res.redirect(`/${slug}`);
});

app.get("/pricing", requireAuth, async (req, res) => {
  await loadDb();

  const reason = req.query.reason || "upgrade";
  const next = sanitizeNext(req.query.next || "/dashboard");
  const requestedPlan = normalizePlanKey(req.query.plan || "plus");
  const selectedPlan = requestedPlan === "pro" ? "pro" : "plus";

  const user = getUserBySession(req);
  const currentPlan = resolveCurrentPlan(user);

  res.render("pricing", {
    reason,
    next,
    currentPlan,
    selectedPlan,
    plusPriceINR: PLAN_DEFINITIONS.plus.priceINR,
    proPriceINR: PLAN_DEFINITIONS.pro.priceINR,
    razorpayKeyId,
    canCustomize: canCustomizePortfolio(user),
    canUseBuilder: canUseWebsiteBuilder(user)
  });
});

app.post("/api/razorpay/order", requireAuth, async (req, res) => {
  if (!razorpay) {
    return res.status(500).json({
      success: false,
      error: "Razorpay is not configured on the server."
    });
  }

  try {
    await loadDb();

    const user = getUserBySession(req);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: "User session not found."
      });
    }

    const requestedPlan = normalizePlanKey(req.body.plan || "plus");
    if (!isPaidPlanKey(requestedPlan)) {
      return res.status(400).json({
        success: false,
        error: "Invalid plan selected."
      });
    }

    const currentPlan = resolveCurrentPlan(user);
    if (getPlanRank(currentPlan) >= getPlanRank(requestedPlan)) {
      return res.status(400).json({
        success: false,
        error: "You already have this plan or a higher plan."
      });
    }

    const amountPaise = getPlanMeta(requestedPlan).priceINR * 100;
    const currency = "INR";
    const receipt = `${requestedPlan}-${user.id}-${Date.now()}`;

    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency,
      receipt
    });

    req.session.pendingPlanPurchase = {
      orderId: order.id,
      plan: requestedPlan,
      createdAt: new Date().toISOString()
    };

    return res.json({
      success: true,
      order_id: order.id,
      amount: amountPaise,
      currency,
      key_id: razorpayKeyId,
      plan: requestedPlan
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error:
        error && typeof error.message === "string"
          ? error.message
          : "Failed to create Razorpay order."
    });
  }
});

app.get("/pay/pro", requireAuth, async (req, res) => {
  const next = sanitizeNext(req.query.next || "/dashboard");
  return res.redirect(`/pricing?reason=upgrade&plan=pro&next=${encodeURIComponent(next)}`);
});

app.post("/payment/verify", requireAuth, async (req, res) => {
  if (!razorpay || !razorpayKeySecret) {
    return res.status(500).json({
      success: false,
      error: "Razorpay is not configured on the server."
    });
  }

  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    next
  } = req.body || {};

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({
      success: false,
      error: "Missing Razorpay verification fields."
    });
  }

  const expectedSignature = crypto
    .createHmac("sha256", razorpayKeySecret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest("hex");

  const isValid = expectedSignature === razorpay_signature;

  if (!isValid) {
    return res.status(400).json({
      success: false,
      error: "Payment verification failed."
    });
  }

  await loadDb();

  const user = getUserBySession(req);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: "User not found."
    });
  }

  const pending = req.session.pendingPlanPurchase;
  if (!pending || pending.orderId !== razorpay_order_id || !isPaidPlanKey(pending.plan)) {
    return res.status(400).json({
      success: false,
      error: "Purchase session expired. Please create a new order."
    });
  }

  activatePaidPlan(user, pending.plan);
  delete req.session.pendingPlanPurchase;
  await db.write();

  return res.json({
    success: true,
    next: sanitizeNext(next || "/dashboard")
  });
});

app.get("/portfolio/:portfolioId/edit", requireAuth, async (req, res) => {
  await loadDb();

  const identifier = req.params.portfolioId;

  let portfolio = db.data.portfolios.find(
    (item) => item.portfolioId === identifier
  );

  if (!portfolio) {
    portfolio = db.data.portfolios.find(
      (item) => item.slug === identifier || item.id === identifier
    );
  }

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (portfolio.ownerUserId !== req.session.user.id) {
    return res.status(403).send("You are not allowed to edit this portfolio.");
  }

  const editIdentifier = portfolio.portfolioId || portfolio.slug || portfolio.id;

  const user = getUserBySession(req);
  const canCustomize = canCustomizePortfolio(user);
  const canUseBuilder = canUseWebsiteBuilder(user);

  const resolved = resolvePortfolioForView(portfolio);
  const formData = {
    ...portfolio,
    portfolioId: editIdentifier,
    aboutCardsText: toPipeRows(portfolio.aboutCards, ["title", "description"]),
    projectsText: toPipeRows(portfolio.projects, [
      "title",
      "platform",
      "description"
    ]),
    experiencesText: toPipeRows(portfolio.experiences, [
      "period",
      "title",
      "description"
    ]),
    shippingPointsText: (portfolio.shippingPoints || []).join("\n"),
    theme: resolved.theme,
    styleTheme: resolved.styleTheme,
    layoutVariant: resolved.layoutVariant,
    sectionOrder: resolved.sectionOrder.join(","),
    heroLayout: resolved.heroLayout,
    aboutLayout: resolved.aboutLayout,
    projectsLayout: resolved.projectsLayout,
    experienceLayout: resolved.experienceLayout,
    showNavbar: resolved.showNavbar ? "1" : "0",
    showFooterContact: resolved.showFooterContact ? "1" : "0",
    fontFamily: resolved.fontFamily,
    fontScale: resolved.fontScale,
    colorBg: resolved.colorBg,
    colorText: resolved.colorText,
    colorAccent: resolved.colorAccent,
    colorCard: resolved.colorCard,
    profileImageUrl: resolved.profileImageUrl,
    companyLogoUrl: resolved.companyLogoUrl
  };

  return res.render("edit-portfolio", { portfolio: formData, canCustomize, canUseBuilder });
});

app.post(
  "/portfolio/:portfolioId/edit",
  requireAuth,
  handlePortfolioImageUpload,
  async (req, res) => {
  await loadDb();

  const identifier = req.params.portfolioId;

  const portfolio =
    db.data.portfolios.find((item) => item.portfolioId === identifier) ||
    db.data.portfolios.find(
      (item) => item.slug === identifier || item.id === identifier
    );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (portfolio.ownerUserId !== req.session.user.id) {
    return res.status(403).send("You are not allowed to edit this portfolio.");
  }

  const user = getUserBySession(req);
  const canCustomize = canCustomizePortfolio(user);
  applyUploadedImageUrlsToRequest(req, user);

  const payload = buildPortfolioPayload(req);
  if (!canCustomize) {
    payload.theme = portfolio.theme;
    payload.layoutVariant = portfolio.layoutVariant;
    payload.sectionOrder = portfolio.sectionOrder;
    payload.heroLayout = portfolio.heroLayout;
    payload.aboutLayout = portfolio.aboutLayout;
    payload.projectsLayout = portfolio.projectsLayout;
    payload.experienceLayout = portfolio.experienceLayout;
    payload.showNavbar = portfolio.showNavbar;
    payload.showFooterContact = portfolio.showFooterContact;
    payload.colorBg = portfolio.colorBg;
    payload.colorText = portfolio.colorText;
    payload.colorAccent = portfolio.colorAccent;
    payload.colorCard = portfolio.colorCard;
    payload.fontFamily = portfolio.fontFamily;
    payload.fontScale = portfolio.fontScale;
    payload.styleTheme = portfolio.styleTheme;
  }
  const previousFullName = portfolio.fullName;

  Object.assign(portfolio, payload, {
    updatedAt: new Date().toISOString()
  });

  if (payload.fullName !== previousFullName) {
    portfolio.slug = uniqueSlugFromName(
      payload.fullName,
      db.data.portfolios.filter((item) => item !== portfolio)
    );
  }

  applyPortfolioDefaults(portfolio);
  await db.write();

  return res.redirect("/dashboard");
  }
);

app.get("/portfolio/:portfolioId/builder", requireAuth, async (req, res) => {
  await loadDb();

  const identifier = req.params.portfolioId;
  const portfolio =
    db.data.portfolios.find((item) => item.portfolioId === identifier) ||
    db.data.portfolios.find(
      (item) => item.slug === identifier || item.id === identifier
    );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (portfolio.ownerUserId !== req.session.user.id) {
    return res.status(403).send("You are not allowed to edit this portfolio.");
  }

  const user = getUserBySession(req);
  if (!canUseWebsiteBuilder(user)) {
    return res.redirect(
      `/pricing?reason=builder&plan=pro&next=${encodeURIComponent(req.originalUrl)}`
    );
  }

  const builder = normalizeBuilderConfig(portfolio.builder);
  return res.render("builder", {
    portfolio,
    planLabel: getPlanLabel(user),
    initialBuilderJson: JSON.stringify(builder),
    livePageUrl: `/${portfolio.slug}`
  });
});

app.post("/portfolio/:portfolioId/builder", requireAuth, async (req, res) => {
  await loadDb();

  const identifier = req.params.portfolioId;
  const portfolio =
    db.data.portfolios.find((item) => item.portfolioId === identifier) ||
    db.data.portfolios.find(
      (item) => item.slug === identifier || item.id === identifier
    );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (portfolio.ownerUserId !== req.session.user.id) {
    return res.status(403).send("You are not allowed to edit this portfolio.");
  }

  const user = getUserBySession(req);
  if (!canUseWebsiteBuilder(user)) {
    return res.redirect(
      `/pricing?reason=builder&plan=pro&next=${encodeURIComponent(req.originalUrl)}`
    );
  }

  let parsedBuilder = {};
  try {
    parsedBuilder = JSON.parse(String(req.body.builderPayload || "{}"));
  } catch {
    parsedBuilder = {};
  }

  portfolio.builder = normalizeBuilderConfig({
    enabled: true,
    sections: parsedBuilder.sections,
    settings: parsedBuilder.settings,
    htmlSnapshot: parsedBuilder.htmlSnapshot
  });
  portfolio.updatedAt = new Date().toISOString();
  await db.write();

  return res.redirect(`/${portfolio.slug}`);
});

app.post("/portfolio/:portfolioId/delete", requireAuth, async (req, res) => {
  await loadDb();

  const identifier = req.params.portfolioId;
  const portfolio =
    db.data.portfolios.find((item) => item.portfolioId === identifier) ||
    db.data.portfolios.find(
      (item) => item.slug === identifier || item.id === identifier
    );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (portfolio.ownerUserId !== req.session.user.id) {
    return res.status(403).send("You are not allowed to delete this portfolio.");
  }

  db.data.portfolios = db.data.portfolios.filter((item) => item !== portfolio);
  await db.write();

  return res.redirect("/dashboard");
});

app.get("/asset/:token", async (req, res) => {
  await loadDb();

  const token = (req.params.token || "").trim();
  if (!token) {
    return res.status(404).send("Asset not found.");
  }

  let foundAsset = null;
  for (const user of db.data.users) {
    const asset = (user.uploadedAssets || []).find((a) => a.token === token);
    if (asset) {
      foundAsset = asset;
      break;
    }
  }

  if (!foundAsset) {
    return res.status(404).send("Asset not found.");
  }

  const safeName = path.basename(foundAsset.storedName || "");
  if (!safeName) {
    return res.status(404).send("Asset not found.");
  }

  const filePath = path.join(uploadsDir, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Asset file missing.");
  }

  if (foundAsset.mimeType) {
    res.type(foundAsset.mimeType);
  }
  return res.sendFile(filePath);
});

app.get("/api/portfolios", async (req, res) => {
  await loadDb();
  return res.json(db.data.portfolios);
});

app.post("/api/portfolio/preview", requireAuth, (req, res) => {
  try {
    const previewReq = {
      body: { ...req.body },
      uploadedImageUrls: {}
    };
    const payload = buildPortfolioPayload(previewReq);
    applyPortfolioDefaults(payload);
    const resolved = resolvePortfolioForView(payload);

    return res.render(
      "portfolio",
      {
        portfolio: resolved,
        outboundHref: (targetUrl) => String(targetUrl || "").trim()
      },
      (err, html) => {
        if (err) {
          console.error("Portfolio preview render failed:", err);
          return res.status(500).send("Preview render failed.");
        }
        return res.type("html").send(html);
      }
    );
  } catch (error) {
    console.error("Portfolio preview build failed:", error);
    return res.status(500).send("Preview render failed.");
  }
});

app.post("/api/analytics/engage", async (req, res) => {
  await loadDb();

  const slug = String(req.body.slug || "").trim();
  if (!slug) {
    return res.status(400).json({ success: false, error: "Missing slug." });
  }

  const portfolio = db.data.portfolios.find((item) => item.slug === slug);
  if (!portfolio) {
    return res.status(404).json({ success: false, error: "Portfolio not found." });
  }

  if (isLikelyBotUserAgent(req.get("user-agent") || "")) {
    return res.json({ success: true, skipped: true });
  }

  trackPortfolioAnalyticsEvent(portfolio, req, {
    type: "engagement",
    visitorId: req.body.visitorId,
    sessionId: req.body.sessionId,
    engagedMs: req.body.engagedMs,
    scrollDepth: req.body.scrollDepth
  });

  await db.write();
  return res.json({ success: true });
});

app.get("/out", async (req, res) => {
  await loadDb();

  const slug = String(req.query.slug || "").trim();
  const sig = String(req.query.sig || "").trim();
  let target;
  try {
    target = decodeURIComponent(String(req.query.u ?? ""));
  } catch {
    return res.status(400).send("Invalid request.");
  }

  if (!slug || !sig || !isSafeOutboundTarget(target)) {
    return res.status(400).send("Invalid request.");
  }

  const portfolio = db.data.portfolios.find((item) => item.slug === slug);
  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  const expected = signOutboundLink(slug, target);
  if (!/^[a-f0-9]{64}$/i.test(sig)) {
    return res.status(403).send("Invalid link.");
  }
  const sigBuf = Buffer.from(sig, "hex");
  const expBuf = Buffer.from(expected, "hex");
  if (sigBuf.length !== expBuf.length) {
    return res.status(403).send("Invalid link.");
  }
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) {
    return res.status(403).send("Invalid link.");
  }

  if (!isLikelyBotUserAgent(req.get("user-agent") || "")) {
    const visitorId = getOrCreateVisitorId(req, res);
    trackPortfolioAnalyticsEvent(portfolio, req, {
      type: "link_click",
      targetUrl: target,
      visitorId
    });
    await db.write();
  }

  return res.redirect(302, target);
});

app.get("/:slug", async (req, res) => {
  await loadDb();

  const portfolio = db.data.portfolios.find(
    (item) => item.slug === req.params.slug
  );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  if (!isLikelyBotUserAgent(req.get("user-agent") || "")) {
    const visitorId = getOrCreateVisitorId(req, res);
    trackPortfolioAnalyticsEvent(portfolio, req, {
      type: "view",
      visitorId
    });
    await db.write();
  }

  const builder = normalizeBuilderConfig(portfolio.builder);
  const hasBuilderContent = builder.sections.some(
    (section) => Array.isArray(section.elements) && section.elements.length > 0
  );
  if (builder.enabled && builder.htmlSnapshot) {
    return res.type("html").send(builder.htmlSnapshot);
  }
  if (builder.enabled && hasBuilderContent) {
    return res.render("portfolio-builder-render", {
      portfolio: resolvePortfolioForView(portfolio),
      builder,
      outboundHref: (targetUrl) => buildTrackedOutboundHref(portfolio.slug, targetUrl)
    });
  }

  return res.render("portfolio", {
    portfolio: resolvePortfolioForView(portfolio),
    outboundHref: (targetUrl) => buildTrackedOutboundHref(portfolio.slug, targetUrl)
  });
});

app.listen(PORT, () => {
  console.log(`Dynamic portfolio app running on http://localhost:${PORT}`);
});