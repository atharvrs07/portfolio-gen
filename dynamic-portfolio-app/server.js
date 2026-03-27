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
const PORT = process.env.PORT || 3000;
const nanoid = customAlphabet("abcdefghijklmnopqrstuvwxyz0123456789", 8);

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

const PRO_PRICE_INR = 450;
const PRO_DURATION_DAYS = 30;

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

function uniqueSlugFromName(fullName, portfolios) {
  const base = slugifyName(fullName) || `portfolio-${nanoid()}`;
  let slug = base;
  let counter = 2;

  while (portfolios.some((item) => item.slug === slug)) {
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

function resolvePortfolioForView(record) {
  const theme = normalizeTheme(record.theme);
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

function applyPortfolioDefaults(record) {
  if (!Array.isArray(record.shippingPoints)) record.shippingPoints = [];
  if (!Array.isArray(record.aboutCards)) record.aboutCards = [];
  if (!Array.isArray(record.projects)) record.projects = [];
  if (!Array.isArray(record.experiences)) record.experiences = [];
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
  });

  db.data.users.forEach((user) => {
    if (!user.plan) {
      user.plan = "basic";
      needsWrite = true;
    }

    if (!user.planStatus) {
      user.planStatus = user.plan === "pro" ? "active" : "inactive";
      needsWrite = true;
    }

    if (user.plan === "pro" && user.planExpiresAt) {
      const expired = new Date(user.planExpiresAt).getTime() <= Date.now();
      if (expired) {
        user.plan = "basic";
        user.planStatus = "expired";
        needsWrite = true;
      }
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

function hasActivePro(user) {
  if (!user) return false;
  if (user.plan !== "pro") return false;
  if (user.planStatus !== "active") return false;
  if (!user.planExpiresAt) return false;

  return new Date(user.planExpiresAt).getTime() > Date.now();
}

function activateProPlan(user) {
  const now = new Date();
  const expiresAt = addDays(now, PRO_DURATION_DAYS);

  user.plan = "pro";
  user.planStatus = "active";
  user.proActivatedAt = now.toISOString();
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
    plan: "basic",
    planStatus: "inactive",
    planExpiresAt: null
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
  const isPro = hasActivePro(user);

  const myPortfolios = db.data.portfolios.filter(
    (item) => item.ownerUserId === req.session.user.id
  );

  res.render("dashboard", {
    portfolios: myPortfolios,
    isPro,
    planLabel: isPro ? "Pro" : "Basic Plan"
  });
});

app.get("/form.html", requireAuth, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const isPro = hasActivePro(user);

  const myPortfolioCount = db.data.portfolios.filter(
    (p) => p.ownerUserId === req.session.user.id
  ).length;

  if (!isPro && myPortfolioCount >= 1) {
    return res.redirect(
      `/pricing?reason=create&next=${encodeURIComponent("/form.html")}`
    );
  }

  return res.render("form");
});

app.post("/create", requireAuth, handlePortfolioImageUpload, async (req, res) => {
  await loadDb();
  await claimLegacyPortfoliosForUser(req.session.user);

  const user = getUserBySession(req);
  const isPro = hasActivePro(user);
  applyUploadedImageUrlsToRequest(req, user);

  const myPortfolioCount = db.data.portfolios.filter(
    (p) => p.ownerUserId === req.session.user.id
  ).length;

  if (!isPro && myPortfolioCount >= 1) {
    return res.redirect(
      `/pricing?reason=create&next=${encodeURIComponent("/form.html")}`
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

  const user = getUserBySession(req);
  const isPro = hasActivePro(user);

  res.render("pricing", {
    reason,
    next,
    plan: isPro ? "pro" : "basic",
    razorpayKeyId,
    proPriceINR: PRO_PRICE_INR
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

    const amountPaise = PRO_PRICE_INR * 100;
    const currency = "INR";
    const receipt = `pro-${user.id}-${Date.now()}`;

    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency,
      receipt
    });

    return res.json({
      success: true,
      order_id: order.id,
      amount: amountPaise,
      currency,
      key_id: razorpayKeyId
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
  await loadDb();

  const next = sanitizeNext(req.query.next || "/dashboard");
  const user = getUserBySession(req);
  const isPro = hasActivePro(user);

  if (isPro) {
    return res.redirect(next);
  }

  if (!razorpay) {
    return res.status(500).render("pricing", {
      reason: "upgrade",
      next,
      plan: "basic",
      razorpayKeyId,
      proPriceINR: PRO_PRICE_INR
    });
  }

  try {
    const amountPaise = PRO_PRICE_INR * 100;
    const currency = "INR";
    const receipt = `pro-${req.session.user.id}-${Date.now()}`;

    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency,
      receipt
    });

    return res.render("razorpay-checkout", {
      next,
      razorpayKeyId,
      proPriceINR: PRO_PRICE_INR,
      orderId: order.id,
      amount: amountPaise,
      currency
    });
  } catch (error) {
    return res.status(500).send(
      error && typeof error.message === "string"
        ? error.message
        : "Failed to start checkout."
    );
  }
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

  activateProPlan(user);
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
  const isPro = hasActivePro(user);

  if (!isPro) {
    const nextUrl = `/portfolio/${encodeURIComponent(editIdentifier)}/edit`;
    return res.redirect(
      `/pricing?reason=edit&next=${encodeURIComponent(nextUrl)}`
    );
  }

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

  return res.render("edit-portfolio", { portfolio: formData });
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
  const isPro = hasActivePro(user);
  applyUploadedImageUrlsToRequest(req, user);

  if (!isPro) {
    const nextUrl = `/portfolio/${encodeURIComponent(identifier)}/edit`;
    return res.redirect(
      `/pricing?reason=edit&next=${encodeURIComponent(nextUrl)}`
    );
  }

  const payload = buildPortfolioPayload(req);
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

app.get("/:slug", async (req, res) => {
  await loadDb();

  const portfolio = db.data.portfolios.find(
    (item) => item.slug === req.params.slug
  );

  if (!portfolio) {
    return res.status(404).send("Portfolio not found.");
  }

  return res.render("portfolio", {
    portfolio: resolvePortfolioForView(portfolio)
  });
});

app.listen(PORT, () => {
  console.log(`Dynamic portfolio app running on http://localhost:${PORT}`);
});