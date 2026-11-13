import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const ORIGIN = "https://its.iust.ac.ir";
const LMS_ORIGIN = "https://lms.iust.ac.ir";
const ALLOWED_ORIGINS = new Set([ORIGIN, LMS_ORIGIN]);
const HOME_PATH = "/";
const LOGIN_PATH = "/oauth2/autheticate";
const DASHBOARD_PATH = "/servicedesk";
const MAX_REDIRECTS = 10;
const MAX_PAGE_TEXT = 40_000;
const MAX_PAGE_TEXT_LIMIT = 200_000;
const SESSION_MAX_AGE_MS = 10 * 60 * 1000;

class PortalError extends Error {}

class CookieJar {
  #cookies = new Map();

  absorb(response, requestUrl) {
    const request = new URL(requestUrl);
    const requestHost = request.hostname.toLowerCase();
    const defaultPath = request.pathname.slice(0, Math.max(1, request.pathname.lastIndexOf("/"))) || "/";
    const setCookies = response.headers.getSetCookie?.() ?? [];
    for (const header of setCookies) {
      const parts = header.split(";");
      const pair = parts.shift() ?? "";
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      const attributes = new Map();
      for (const part of parts) {
        const index = part.indexOf("=");
        const key = (index < 0 ? part : part.slice(0, index)).trim().toLowerCase();
        const attrValue = index < 0 ? "" : part.slice(index + 1).trim();
        if (key) attributes.set(key, attrValue);
      }
      const hostOnly = !attributes.has("domain");
      const domain = String(attributes.get("domain") || requestHost).replace(/^\./, "").toLowerCase();
      if (requestHost !== domain && !requestHost.endsWith(`.${domain}`)) continue;
      const path = attributes.get("path")?.startsWith("/") ? attributes.get("path") : defaultPath;
      const key = `${name}\u0000${domain}\u0000${path}`;
      const maxAge = Number.parseInt(attributes.get("max-age"), 10);
      const expiresAt = attributes.has("expires") ? Date.parse(attributes.get("expires")) : undefined;
      if (!value || (Number.isFinite(maxAge) && maxAge <= 0) || (Number.isFinite(expiresAt) && expiresAt <= Date.now())) {
        this.#cookies.delete(key);
        continue;
      }
      this.#cookies.set(key, {
        name,
        value,
        domain,
        hostOnly,
        path,
        secure: attributes.has("secure"),
        expiresAt: Number.isFinite(maxAge) && maxAge > 0
          ? Date.now() + maxAge * 1000
          : Number.isFinite(expiresAt) ? expiresAt : undefined,
      });
    }
  }

  header(requestUrl) {
    const url = new URL(requestUrl);
    const host = url.hostname.toLowerCase();
    return [...this.#cookies.values()]
      .filter((cookie) => {
        const domainMatches = cookie.hostOnly
          ? host === cookie.domain
          : host === cookie.domain || host.endsWith(`.${cookie.domain}`);
        const pathMatches = url.pathname === cookie.path ||
          url.pathname.startsWith(cookie.path.endsWith("/") ? cookie.path : `${cookie.path}/`);
        return domainMatches && pathMatches && (!cookie.secure || url.protocol === "https:") &&
          (cookie.expiresAt === undefined || cookie.expiresAt > Date.now());
      })
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ");
  }
}

function assertPortalUrl(value) {
  const url = new URL(value, ORIGIN);
  if (!ALLOWED_ORIGINS.has(url.origin) || url.username || url.password) {
    throw new PortalError("Requests are limited to the IUST IT portal and LMS HTTPS origins.");
  }
  return url;
}

function assertLmsUrl(value) {
  const url = assertPortalUrl(value);
  if (url.origin !== LMS_ORIGIN) throw new PortalError("LMS page and write requests must stay on lms.iust.ac.ir.");
  return url;
}

function portalPath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
    throw new PortalError("Use a path beginning with / on its.iust.ac.ir.");
  }
  const url = assertPortalUrl(new URL(value, ORIGIN));
  url.hash = "";
  return url;
}

function lmsPath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
    throw new PortalError("Use a path beginning with / on lms.iust.ac.ir.");
  }
  const url = assertLmsUrl(new URL(value, LMS_ORIGIN));
  url.hash = "";
  return url;
}

async function portalRequest(jar, startUrl, options = {}) {
  let url = assertPortalUrl(startUrl);
  let method = (options.method ?? "GET").toUpperCase();
  let body = options.body;
  let referer = options.referer ? assertPortalUrl(options.referer).toString() : null;

  for (let step = 0; step <= MAX_REDIRECTS; step += 1) {
    const refererUrl = referer ? assertPortalUrl(referer) : null;
    const sameSite = refererUrl && refererUrl.hostname.endsWith(".iust.ac.ir") && url.hostname.endsWith(".iust.ac.ir");
    const headers = {
      accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate, br, zstd",
      "user-agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
      "upgrade-insecure-requests": "1",
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": refererUrl
        ? refererUrl.origin === url.origin ? "same-origin" : sameSite ? "same-site" : "cross-site"
        : "none",
      "sec-fetch-user": "?1",
      priority: "u=0, i",
    };
    if (refererUrl) headers.referer = refererUrl.origin === url.origin ? refererUrl.toString() : `${refererUrl.origin}/`;
    if (method !== "GET" && method !== "HEAD") headers.origin = url.origin;
    if (options.contentType) headers["content-type"] = options.contentType;
    else if (body !== undefined) headers["content-type"] = "application/x-www-form-urlencoded";
    for (const [name, value] of Object.entries(options.extraHeaders ?? {})) {
      const normalized = name.toLowerCase();
      if (["host", "cookie", "origin", "referer", "content-length", "content-type", "connection", "transfer-encoding"].includes(normalized) || normalized.startsWith("sec-")) {
        throw new PortalError(`The ${name} header is controlled by the MCP server.`);
      }
      headers[normalized] = value;
    }
    const cookie = jar.header(url);
    if (cookie) headers.cookie = cookie;

    let response;
    try {
      response = await fetch(url, { method, headers, body, redirect: "manual" });
    } catch {
      throw new PortalError("Could not reach the IUST portal.");
    }
    jar.absorb(response, url);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new PortalError("The portal returned an incomplete redirect.");
      referer = url.toString();
      url = assertPortalUrl(new URL(location, url).toString());
      if (response.status === 303 || ([301, 302].includes(response.status) && method !== "GET")) {
        method = "GET";
        body = undefined;
      }
      continue;
    }

    if (!response.ok) {
      throw new PortalError(`The IUST portal returned HTTP ${response.status} at ${url.pathname}.`);
    }
    return { response, url };
  }
  throw new PortalError("The portal returned too many redirects.");
}

function readAttribute(tag, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = tag.match(new RegExp(`\\b${escapedName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? "";
}

function htmlText(value) {
  return value
    .replace(/&#(x[\da-f]+|\d+);/gi, (_match, code) => {
      const number = code.toLowerCase().startsWith("x")
        ? Number.parseInt(code.slice(1), 16)
        : Number.parseInt(code, 10);
      return Number.isInteger(number) && number >= 0 && number <= 0x10ffff
        ? String.fromCodePoint(number)
        : _match;
    })
    .replaceAll("&nbsp;", " ")
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">");
}

function addFormValue(fields, name, value) {
  if (!name) return;
  if (!Object.hasOwn(fields, name)) {
    fields[name] = value;
  } else if (Array.isArray(fields[name])) {
    fields[name].push(value);
  } else {
    fields[name] = [fields[name], value];
  }
}

function parseFormMarkup(form) {
  const openingTag = form.match(/<form\b[^>]*>/i)?.[0] ?? form;
  const fields = {};
  const fieldTypes = {};
  const controls = form.match(/<(?:input|button)\b[^>]*>/gi) ?? [];

  for (const control of controls) {
    if (/\bdisabled\b/i.test(control)) continue;
    const name = htmlText(readAttribute(control, "name"));
    if (!name) continue;
    const type = (readAttribute(control, "type") || "text").toLowerCase();
    if (["checkbox", "radio"].includes(type) && !/\bchecked\b/i.test(control)) continue;
    addFormValue(fields, name, htmlText(readAttribute(control, "value")));
    fieldTypes[name] = type;
  }

  const textareas = form.match(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi) ?? [];
  for (const textarea of textareas) {
    const opening = textarea.match(/<textarea\b[^>]*>/i)?.[0] ?? textarea;
    const name = htmlText(readAttribute(opening, "name"));
    if (!name || /\bdisabled\b/i.test(opening)) continue;
    const value = textarea.replace(/^<textarea\b[^>]*>/i, "").replace(/<\/textarea>\s*$/i, "");
    addFormValue(fields, name, htmlText(value));
    fieldTypes[name] = "textarea";
  }

  const selects = form.match(/<select\b[^>]*>[\s\S]*?<\/select>/gi) ?? [];
  for (const select of selects) {
    const opening = select.match(/<select\b[^>]*>/i)?.[0] ?? select;
    const name = htmlText(readAttribute(opening, "name"));
    if (!name || /\bdisabled\b/i.test(opening)) continue;
    const options = select.match(/<option\b[^>]*>[\s\S]*?<\/option>/gi) ?? [];
    const selected = options.filter((option) => /\bselected\b/i.test(option.match(/<option\b[^>]*>/i)?.[0] ?? ""));
    const chosen = selected.length ? selected : options.slice(0, 1);
    for (const option of chosen) {
      const openingOption = option.match(/<option\b[^>]*>/i)?.[0] ?? option;
      const rawValue = readAttribute(openingOption, "value");
      const value = rawValue || option.replace(/^<option\b[^>]*>/i, "").replace(/<\/option>\s*$/i, "").replace(/<[^>]*>/g, "");
      addFormValue(fields, name, htmlText(value));
    }
    fieldTypes[name] = "select";
  }

  return {
    elementId: readAttribute(openingTag, "id"),
    action: htmlText(readAttribute(openingTag, "action")),
    method: (readAttribute(openingTag, "method") || "GET").toUpperCase(),
    fields,
    fieldTypes,
  };
}

function parseForms(html) {
  return (html.match(/<form\b[^>]*>[\s\S]*?<\/form>/gi) ?? []).map(parseFormMarkup);
}

function extractForm(html, { elementId, hiddenFormId, requiredFields = [] } = {}) {
  return parseForms(html).find((form) => {
    if (elementId && form.elementId !== elementId) return false;
    if (hiddenFormId && form.fields.form_id !== hiddenFormId) return false;
    if (requiredFields.some((field) => !Object.hasOwn(form.fields, field))) return false;
    if (requiredFields.includes("form_build_id") && !form.fields.form_build_id) return false;
    return true;
  }) ?? null;
}

function extractDirectLoginForm(html) {
  const form = extractForm(html, {
    hiddenFormId: "oauth2_server_authenticate_form",
    requiredFields: ["form_build_id", "form_id"],
  });
  if (!form) throw new PortalError("The direct username/password login form was not found.");
  if (!Object.hasOwn(form.fields, "name") || !Object.hasOwn(form.fields, "pass")) {
    throw new PortalError("The direct login form did not render username/password fields.");
  }
  return form;
}

function extractLmsIdentityProviderUrl(html, pageUrl) {
  const links = html.match(/<a\b[^>]*>/gi) ?? [];
  const link = links.find((tag) =>
    readAttribute(tag, "class").split(/\s+/).includes("login-identityprovider-btn"),
  );
  if (!link) throw new PortalError("The LMS identity-provider button was not found.");
  const href = htmlText(readAttribute(link, "href"));
  const url = assertLmsUrl(new URL(href, pageUrl));
  if (url.pathname !== "/auth/oauth2/login.php") {
    throw new PortalError("The LMS identity-provider button points to an unexpected login route.");
  }
  return url;
}

function extractHomepageLoginForm(html) {
  const form = extractForm(html, {
    elementId: "openid-connect-login-form",
    requiredFields: ["its", "form_build_id", "form_id"],
  });
  if (!form) throw new PortalError("The IUST homepage login form was not found.");
  return form;
}

function formBody(fields) {
  const params = new URLSearchParams();
  for (const [name, rawValue] of Object.entries(fields)) {
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) params.append(name, String(value));
  }
  return params.toString();
}

async function beginDirectLogin(jar) {
  const homepage = await portalRequest(jar, `${ORIGIN}${HOME_PATH}`);
  const homeUrl = homepage.url.toString();
  const homeForm = extractHomepageLoginForm(await homepage.response.text());
  const homePostUrl = new URL(homeForm.action || HOME_PATH, homeUrl).toString();
  const bootstrap = await portalRequest(jar, homePostUrl, {
    method: "POST",
    body: formBody(homeForm.fields),
    referer: homeUrl,
  });
  const loginForm = extractDirectLoginForm(await bootstrap.response.text());
  return { loginForm, loginUrl: bootstrap.url.toString() };
}

async function beginLmsLogin(jar) {
  const loginPage = await portalRequest(jar, `${LMS_ORIGIN}/login/index.php`);
  const loginHtml = await loginPage.response.text();
  const identityProviderUrl = extractLmsIdentityProviderUrl(loginHtml, loginPage.url);
  const identityProviderPage = await portalRequest(jar, identityProviderUrl, {
    referer: loginPage.url.toString(),
  });
  if (identityProviderPage.url.origin !== ORIGIN || identityProviderPage.url.pathname !== LOGIN_PATH) {
    throw new PortalError("The LMS sign-in flow did not reach the IUST direct-login page.");
  }
  const loginForm = extractDirectLoginForm(await identityProviderPage.response.text());
  return {
    loginForm,
    loginUrl: identityProviderPage.url.toString(),
    identityProviderUrl: identityProviderUrl.toString(),
  };
}

function extractDashboard(html, dashboardUrl) {
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "";
  const links = [];
  const seen = new Set();
  const anchors = html.match(/<a\b[^>]*>[\s\S]*?<\/a>/gi) ?? [];
  let authenticated = false;

  for (const anchor of anchors) {
    const openingTag = anchor.match(/<a\b[^>]*>/i)?.[0] ?? anchor;
    const href = htmlText(readAttribute(openingTag, "href")).trim();
    const label = htmlText(anchor.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
    if (href.includes("/user/logout")) authenticated = true;
    if (!href || !label || href.startsWith("#") || href.startsWith("javascript:")) continue;
    if (href.includes("/user/logout") || label === "خروج" || label === "Logout") continue;

    let absolute;
    try {
      absolute = new URL(href, dashboardUrl);
    } catch {
      continue;
    }
    if (!["http:", "https:"].includes(absolute.protocol)) continue;
    const normalized = absolute.toString();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    links.push({ name: label, url: normalized });
  }

  return {
    authenticated,
    pageTitle: htmlText(title).replace(/\s+/g, " ").trim(),
    services: links,
  };
}

function loginFormRendered(html) {
  return /<input\b[^>]*\bname\s*=\s*["']pass["']/i.test(html);
}

function htmlToText(html) {
  const body = html.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i)?.[1] ?? html;
  return htmlText(body
    .replace(/<(script|style|noscript)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\b[^>]*>/gi, "\n")
    .replace(/<\/(?:p|div|li|tr|h[1-6]|section|article|table|form)\s*>/gi, "\n")
    .replace(/<[^>]*>/g, " "))
    .replace(/[\t\f\r ]+/g, " ")
    .replace(/ *\n+ */g, "\n")
    .trim();
}

function safeVisibleUrl(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

function summarizeForms(html, pageUrl) {
  return parseForms(html).map((form) => ({
    id: form.elementId || form.fields.form_id || "",
    formId: typeof form.fields.form_id === "string" ? form.fields.form_id : "",
    method: form.method,
    action: safeVisibleUrl(form.action || pageUrl, pageUrl),
    fieldNames: Object.keys(form.fields),
  }));
}

function summarizeLinks(html, pageUrl) {
  const links = [];
  const seen = new Set();
  for (const anchor of html.match(/<a\b[^>]*>[\s\S]*?<\/a>/gi) ?? []) {
    const openingTag = anchor.match(/<a\b[^>]*>/i)?.[0] ?? anchor;
    const url = safeVisibleUrl(htmlText(readAttribute(openingTag, "href")), pageUrl);
    const label = htmlText(anchor.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
    if (!url || !label || seen.has(`${label}\u0000${url}`)) continue;
    seen.add(`${label}\u0000${url}`);
    links.push({ name: label, url });
  }
  return links;
}

function pageResult(html, response, url, maxChars = MAX_PAGE_TEXT) {
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "";
  const text = htmlToText(html);
  return {
    path: url.pathname,
    status: response.status,
    contentType: response.headers.get("content-type") ?? "",
    pageTitle: htmlText(title).replace(/\s+/g, " ").trim(),
    text: text.slice(0, maxChars),
    forms: summarizeForms(html, url),
    links: summarizeLinks(html, url),
    textTruncated: text.length > maxChars,
  };
}

let activeSession = null;
let activeSessionAt = 0;
let activeLmsSession = null;
let activeLmsSessionAt = 0;
let sessionQueue = Promise.resolve();

async function serialized(operation) {
  const previous = sessionQueue;
  let release;
  sessionQueue = new Promise((resolve) => { release = resolve; });
  await previous;
  try {
    return await operation();
  } finally {
    release();
  }
}

async function authenticatePortal() {
  const username = process.env.IUST_USERNAME;
  const password = process.env.IUST_PASSWORD;
  if (!username || !password) {
    throw new PortalError("Set IUST_USERNAME and IUST_PASSWORD in the MCP server environment, then restart it.");
  }

  const jar = new CookieJar();
  const { loginForm, loginUrl } = await beginDirectLogin(jar);
  const postUrl = new URL(loginForm.action || LOGIN_PATH, loginUrl).toString();
  const fields = {
    ...loginForm.fields,
    name: username,
    pass: password,
    op: loginForm.fields.op || "ورود",
  };
  const loginResult = await portalRequest(jar, postUrl, {
    method: "POST",
    body: formBody(fields),
    referer: loginUrl,
  });

  let current = loginResult;
  let dashboard = extractDashboard(await current.response.text(), current.url.toString());
  if (!(dashboard.authenticated && current.url.pathname === DASHBOARD_PATH)) {
    current = await portalRequest(jar, `${ORIGIN}${DASHBOARD_PATH}`);
    dashboard = extractDashboard(await current.response.text(), current.url.toString());
  }
  if (!dashboard.authenticated || current.url.pathname !== DASHBOARD_PATH) {
    throw new PortalError("Login did not reach the authenticated service dashboard. Check the credentials or portal flow.");
  }

  activeSession = jar;
  activeSessionAt = Date.now();
  return { jar, dashboard };
}

async function getPortalSession() {
  if (activeSession && Date.now() - activeSessionAt < SESSION_MAX_AGE_MS) return activeSession;
  return (await authenticatePortal()).jar;
}

async function authenticatedPage(path, options = {}) {
  const url = portalPath(path);
  let jar = await getPortalSession();
  let current = await portalRequest(jar, url, options);
  let html = await current.response.text();
  if (loginFormRendered(html) && url.pathname !== LOGIN_PATH) {
    activeSession = null;
    jar = await getPortalSession();
    current = await portalRequest(jar, url, options);
    html = await current.response.text();
    if (loginFormRendered(html)) {
      throw new PortalError("The portal returned the login form after reauthentication.");
    }
  }
  return { jar, current, html };
}

async function checkConnection() {
  const jar = new CookieJar();
  const { loginForm, loginUrl } = await beginDirectLogin(jar);
  return {
    reachable: true,
    homepageLoginFormFound: true,
    oauthContextEstablished: true,
    loginFormFound: true,
    loginFormPath: new URL(loginUrl).pathname,
    csrfFormTokenFound: Boolean(loginForm.fields.form_build_id),
    credentialInputsRendered: true,
    credentialsSubmitted: false,
  };
}

async function getDashboard() {
  const { jar, dashboard } = await authenticatePortal();
  // Keep the authenticated session for the other read/write tools in this process.
  activeSession = jar;
  return {
    authenticated: true,
    dashboard: `${ORIGIN}${DASHBOARD_PATH}`,
    pageTitle: dashboard.pageTitle,
    services: dashboard.services,
    sessionCookiesPersisted: false,
  };
}

async function readPortalPage(path, headers, maxChars = MAX_PAGE_TEXT) {
  const { current, html } = await authenticatedPage(path, { extraHeaders: headers });
  return { authenticated: true, ...pageResult(html, current.response, current.url, maxChars) };
}

async function submitPortalForm(path, formId, fields, maxChars = MAX_PAGE_TEXT) {
  const page = await authenticatedPage(path);
  const form = parseForms(page.html).find((candidate) =>
    candidate.elementId === formId || candidate.fields.form_id === formId,
  );
  if (!form) throw new PortalError(`No form with id '${formId}' was found on ${page.current.url.pathname}.`);
  if (form.method !== "POST") throw new PortalError("Only POST forms can be submitted with this tool.");

  const actionUrl = assertPortalUrl(new URL(form.action || page.current.url, page.current.url).toString());
  const merged = { ...form.fields, ...fields };
  for (const name of ["form_build_id", "form_id", "form_token", "csrf_token", "_token"]) {
    if (Object.hasOwn(form.fields, name)) merged[name] = form.fields[name];
  }
  const result = await portalRequest(page.jar, actionUrl, {
    method: "POST",
    body: formBody(merged),
    referer: page.current.url.toString(),
  });
  const html = await result.response.text();
  return {
    authenticated: !loginFormRendered(html),
    submitted: true,
    method: "POST",
    path: result.url.pathname,
    response: pageResult(html, result.response, result.url, maxChars),
    reauthenticationNeeded: loginFormRendered(html),
  };
}

async function requestPortal(path, method, body, contentType, headers, maxChars = MAX_PAGE_TEXT) {
  const url = portalPath(path);
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET") {
    return readPortalPage(url.pathname + url.search, headers, maxChars);
  }
  const page = await authenticatedPage(DASHBOARD_PATH);
  const result = await portalRequest(page.jar, url, {
    method: upperMethod,
    body,
    contentType: body === undefined ? undefined : contentType || "application/x-www-form-urlencoded",
    referer: page.current.url.toString(),
    extraHeaders: headers,
  });
  const contentTypeHeader = result.response.headers.get("content-type") ?? "";
  const text = await result.response.text();
  const html = contentTypeHeader.includes("html") ? text : "";
  return {
    authenticated: !html || !loginFormRendered(html),
    completed: true,
    method: upperMethod,
    path: result.url.pathname,
    status: result.response.status,
    contentType: contentTypeHeader,
    response: html ? pageResult(html, result.response, result.url, maxChars) : text.slice(0, maxChars),
    reauthenticationNeeded: Boolean(html && loginFormRendered(html)),
  };
}

function isLmsLoginPage(html, url) {
  return url.origin === LMS_ORIGIN && url.pathname === "/login/index.php" &&
    (/name=["']username["']/i.test(html) || /login-identityprovider-btn/i.test(html));
}

function isLmsDashboard(html, url) {
  if (url.origin !== LMS_ORIGIN || !["/my/", "/my/index.php"].includes(url.pathname)) return false;
  return !isLmsLoginPage(html, url);
}

async function authenticateLms() {
  const username = process.env.IUST_USERNAME;
  const password = process.env.IUST_PASSWORD;
  if (!username || !password) {
    throw new PortalError("Set IUST_USERNAME and IUST_PASSWORD in the MCP server environment, then restart it.");
  }

  const jar = new CookieJar();
  const { loginForm, loginUrl } = await beginLmsLogin(jar);
  const postUrl = assertPortalUrl(new URL(loginForm.action || LOGIN_PATH, loginUrl));
  if (postUrl.origin !== ORIGIN) {
    throw new PortalError("The LMS provider returned a login form outside its.iust.ac.ir.");
  }
  const fields = {
    ...loginForm.fields,
    name: username,
    pass: password,
    op: loginForm.fields.op || "ورود",
  };
  let current = await portalRequest(jar, postUrl, {
    method: "POST",
    body: formBody(fields),
    referer: loginUrl,
  });
  let html = await current.response.text();
  if (!isLmsDashboard(html, current.url)) {
    current = await portalRequest(jar, `${LMS_ORIGIN}/my/`);
    html = await current.response.text();
  }
  if (!isLmsDashboard(html, current.url)) {
    throw new PortalError("The LMS OAuth flow did not reach the authenticated /my/ dashboard.");
  }

  activeLmsSession = jar;
  activeLmsSessionAt = Date.now();
  return { jar, current, html };
}

async function getLmsSession() {
  if (activeLmsSession && Date.now() - activeLmsSessionAt < SESSION_MAX_AGE_MS) return activeLmsSession;
  return (await authenticateLms()).jar;
}

async function authenticatedLmsPage(path, options = {}) {
  const url = lmsPath(path);
  let jar = await getLmsSession();
  let current = await portalRequest(jar, url, options);
  let html = await current.response.text();
  if (isLmsLoginPage(html, current.url) && url.pathname !== "/login/index.php") {
    activeLmsSession = null;
    jar = await getLmsSession();
    current = await portalRequest(jar, url, options);
    html = await current.response.text();
    if (isLmsLoginPage(html, current.url)) {
      throw new PortalError("The LMS returned its login page after reauthentication.");
    }
  }
  return { jar, current, html };
}

async function checkLmsConnection() {
  const jar = new CookieJar();
  const { loginForm, loginUrl, identityProviderUrl } = await beginLmsLogin(jar);
  return {
    reachable: true,
    lmsLoginPageFound: true,
    identityProviderButtonFound: true,
    oauthRequestStarted: true,
    identityProviderPath: new URL(identityProviderUrl).pathname,
    directCredentialFormPath: new URL(loginUrl).pathname,
    credentialInputsRendered: Boolean(loginForm.fields.name !== undefined && loginForm.fields.pass !== undefined),
    credentialsSubmitted: false,
  };
}

async function getLmsDashboard() {
  const { current, html } = await authenticateLms();
  return {
    authenticated: true,
    dashboard: `${LMS_ORIGIN}/my/`,
    ...pageResult(html, current.response, current.url),
    sessionCookiesPersisted: false,
  };
}

async function readLmsPage(path, headers, maxChars = MAX_PAGE_TEXT) {
  const { current, html } = await authenticatedLmsPage(path, { extraHeaders: headers });
  return { authenticated: !isLmsLoginPage(html, current.url), ...pageResult(html, current.response, current.url, maxChars) };
}

async function submitLmsForm(path, formId, fields, maxChars = MAX_PAGE_TEXT) {
  const page = await authenticatedLmsPage(path);
  const form = parseForms(page.html).find((candidate) =>
    candidate.elementId === formId || candidate.fields.form_id === formId,
  );
  if (!form) throw new PortalError(`No form with id '${formId}' was found on ${page.current.url.pathname}.`);
  if (form.method !== "POST") throw new PortalError("Only POST forms can be submitted with this tool.");

  const actionUrl = assertLmsUrl(new URL(form.action || page.current.url, page.current.url));
  const merged = { ...form.fields, ...fields };
  for (const name of ["form_build_id", "form_id", "form_token", "csrf_token", "_token", "sesskey"]) {
    if (Object.hasOwn(form.fields, name)) merged[name] = form.fields[name];
  }
  const result = await portalRequest(page.jar, actionUrl, {
    method: "POST",
    body: formBody(merged),
    referer: page.current.url.toString(),
  });
  const html = await result.response.text();
  return {
    authenticated: !isLmsLoginPage(html, result.url),
    submitted: true,
    method: "POST",
    path: result.url.pathname,
    response: pageResult(html, result.response, result.url, maxChars),
    reauthenticationNeeded: isLmsLoginPage(html, result.url),
  };
}

async function requestLms(path, method, body, contentType, headers, maxChars = MAX_PAGE_TEXT) {
  const url = lmsPath(path);
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET") return readLmsPage(url.pathname + url.search, headers, maxChars);
  const page = await authenticatedLmsPage("/my/");
  const result = await portalRequest(page.jar, url, {
    method: upperMethod,
    body,
    contentType: body === undefined ? undefined : contentType || "application/x-www-form-urlencoded",
    referer: page.current.url.toString(),
    extraHeaders: headers,
  });
  const contentTypeHeader = result.response.headers.get("content-type") ?? "";
  const text = await result.response.text();
  const html = contentTypeHeader.includes("html") ? text : "";
  return {
    authenticated: !html || !isLmsLoginPage(html, result.url),
    completed: true,
    method: upperMethod,
    path: result.url.pathname,
    status: result.response.status,
    contentType: contentTypeHeader,
    response: html ? pageResult(html, result.response, result.url, maxChars) : text.slice(0, maxChars),
    reauthenticationNeeded: Boolean(html && isLmsLoginPage(html, result.url)),
  };
}

const server = new McpServer({ name: "iust-lms-portal", version: "0.3.0" });

async function safeToolResult(operation) {
  try {
    return await operation();
  } catch (error) {
    return {
      authenticated: false,
      error: error instanceof PortalError ? error.message : "The IUST portal request failed.",
    };
  }
}

server.tool(
  "check_portal_connection",
  "Open the IUST homepage login flow and check that it renders the direct username/password form, without submitting credentials.",
  {},
  async () => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(checkConnection)) }] }),
);

server.tool(
  "get_portal_dashboard",
  "Sign in through the homepage OAuth bootstrap and list service links on the IUST dashboard.",
  {},
  async () => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(getDashboard))) }] }),
);

server.tool(
  "read_portal_page",
  "Read page text, links, and form field names from any HTTPS page on its.iust.ac.ir using the authenticated session.",
  {
    path: z.string().describe("A path on its.iust.ac.ir, such as /servicedesk or /user"),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => readPortalPage(path, undefined, max_chars)))) }] }),
);

server.tool(
  "submit_portal_form",
  "Submit a POST form on its.iust.ac.ir with fresh hidden form tokens from that page. This can change portal data.",
  {
    path: z.string().describe("Path of the page containing the form"),
    form_id: z.string().describe("HTML form id or the hidden form_id value"),
    fields: z.record(z.string(), z.union([z.string(), z.array(z.string())])).describe("Form values to set or override"),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, form_id, fields, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => submitPortalForm(path, form_id, fields, max_chars)))) }] }),
);

server.tool(
  "request_portal",
  "Send an authenticated GET, POST, PUT, PATCH, or DELETE request to its.iust.ac.ir. Requests cannot leave this origin; non-GET methods can change portal data.",
  {
    path: z.string().describe("Path on its.iust.ac.ir, including an optional query string"),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
    body: z.string().optional().describe("Raw request body, if required"),
    content_type: z.string().optional().describe("Content-Type for a request body"),
    headers: z.record(z.string(), z.string()).optional().describe("Optional application headers; origin, cookies, and browser security headers remain MCP-controlled"),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, method, body, content_type, headers, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => requestPortal(path, method, body, content_type, headers, max_chars)))) }] }),
);

server.tool(
  "check_lms_connection",
  "Start from the LMS login page, follow its identity-provider OAuth request to ITS, and check that the direct credential form appears without submitting credentials.",
  {},
  async () => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(checkLmsConnection))) }] }),
);

server.tool(
  "get_lms_dashboard",
  "Sign in to the LMS by starting at its identity-provider button, authenticate at ITS, and return the Moodle /my/ dashboard.",
  {},
  async () => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(getLmsDashboard))) }] }),
);

server.tool(
  "read_lms_page",
  "Read page text, links, and form field names from an authenticated page on lms.iust.ac.ir.",
  {
    path: z.string().describe("A path on lms.iust.ac.ir, such as /my/ or /course/view.php?id=..."),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => readLmsPage(path, undefined, max_chars)))) }] }),
);

server.tool(
  "submit_lms_form",
  "Submit a POST form on lms.iust.ac.ir using fresh form tokens. This can change LMS data, including course activity.",
  {
    path: z.string().describe("Path of the LMS page containing the form"),
    form_id: z.string().describe("HTML form id or Moodle form_id value"),
    fields: z.record(z.string(), z.union([z.string(), z.array(z.string())])).describe("Form values to set or override"),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, form_id, fields, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => submitLmsForm(path, form_id, fields, max_chars)))) }] }),
);

server.tool(
  "request_lms",
  "Send an authenticated GET, POST, PUT, PATCH, or DELETE request to lms.iust.ac.ir. Requests cannot leave the LMS origin; non-GET methods can change LMS data.",
  {
    path: z.string().describe("Path on lms.iust.ac.ir, including an optional query string"),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
    body: z.string().optional().describe("Raw request body, if required"),
    content_type: z.string().optional().describe("Content-Type for a request body"),
    headers: z.record(z.string(), z.string()).optional().describe("Optional application headers; origin, cookies, and browser security headers remain MCP-controlled"),
    max_chars: z.number().int().min(1).max(MAX_PAGE_TEXT_LIMIT).default(MAX_PAGE_TEXT),
  },
  async ({ path, method, body, content_type, headers, max_chars }) => ({ content: [{ type: "text", text: JSON.stringify(await safeToolResult(() => serialized(() => requestLms(path, method, body, content_type, headers, max_chars)))) }] }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
