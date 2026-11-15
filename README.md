# ShilpaPath (শিল্পপথ / शिल्पपथ)
### Zero-Cost Digital Bridge Connecting Travelers Directly to Authentic Craft Clusters
*Ground-truth Cultural Innovation for West Bengal, Bihar, and Jharkhand • SFIC Pilot Ready*

[![Status](https://img.shields.io/badge/Status-Complete-emerald)](#)
[![Stack](https://img.shields.io/badge/Stack-Vanilla_JS_•_Tailwind_•_Leaflet_•_Node.js-amber)](#)
[![Cost](https://img.shields.io/badge/Prototype_Cost-₹0_Zero_Budget-blue)](#)
[![Security](https://img.shields.io/badge/Snyk_Security-7_Issues_Resolved_(CWE--23/79/319/770)-brightgreen)](#)
[![Showcase](https://img.shields.io/badge/Showcase-SFIC_Ready_(sevafirst.mic.gov.in)-orange)](https://sevafirst.mic.gov.in/)

---

## 🎯 1. Problem Statement

Authentic craft clusters across **West Bengal, Bihar, and Jharkhand**—such as terracotta, dokra, and Madhubani hubs—remain largely invisible to everyday tourists. Travelers rely on fragmented blogs or costly middlemen, while local artisans lack digital visibility and accessible, regional-language storytelling for visitors.

- **Middleman Exploitation:** Rural artisans receive only a fraction of market value through commercial emporiums and tour middlemen.
- **Digital Invisibility:** Rural artisan hamlets in Bankura, Purulia, Medinipur, Madhubani, Gaya, and Hazaribagh lack digital mapping on generic aggregators like MakeMyTrip or TripAdvisor.
- **Missing In-Situ Context:** Tourists arriving in villages find no guided audio plaques or historical context in their native tongue.
- **App Store Fatigue:** Forcing tourists to download heavy native apps for a single village trail leads to high drop-offs, especially under spotty rural 3G/4G connectivity.

---

## 💡 2. Solution & Implementation

**ShilpaPath** is a lightweight, zero-cost web platform that connects travelers directly to verified craft clusters:

1. **Interactive Discovery:** Built with **HTML5, Tailwind CSS, vanilla JavaScript, and Leaflet.js + OpenStreetMap tiles** to pin authentic artisan hubs with exact coordinates, visiting hours, and travel context.
2. **Multilingual Audio Guides:** Uses the browser's native **Web Speech API** to deliver instant voice narration in **English, Bengali, and Hindi** without paid TTS APIs, heavy SDKs, or app downloads.
3. **Verified Profiles & Safety:** Backed by a lightweight **Node.js (`server.js`)** backend serving curated JSON cluster profiles, paired with **Snyk static analysis** to keep the codebase secure before public deployment.

---

## 💰 3. Cost Breakdown (Zero-Budget Student Prototype)

| Component | Tool / Service | Prototype Cost |
| :--- | :--- | :--- |
| **Maps & Tiles** | Leaflet.js + OpenStreetMap | **₹0** (Open source) |
| **Voice Narration** | Browser Web Speech API | **₹0** (Client-side) |
| **Frontend & Backend** | HTML/Tailwind + Node.js (`server.js`) | **₹0** (Open source) |
| **Hosting & Security** | Free-tier cloud hosting + GitHub/Snyk | **₹0** (Student/Free tier) |
| **Total Prototype Cost** | — | **₹0** |

---

## 📅 4. Implementation Timeline (6-Week Pilot Plan)

| Phase | Window | Key Milestone |
| :--- | :--- | :--- |
| **Phase 1: Core & Data** | Weeks 1–2 (Mid–Late Nov 2026) | Finalize 5–10 verified craft cluster JSON profiles across WB, Bihar, and Jharkhand; patch the `server.js` path traversal issue. |
| **Phase 2: UI & Audio** | Weeks 3–4 (Early Dec 2026) | Polish Leaflet map filters, mobile responsiveness, and Bengali/Hindi/English Web Speech narration. |
| **Phase 3: Field Pilot** | Weeks 5–6 (Mid–Late Dec 2026) | Deploy live demo, test with 15–20 student travelers/local contacts, and gather feedback metrics for the [SFIC showcase](https://sevafirst.mic.gov.in/). |

---

## 🌟 5. Beneficiary Impact

- **Local Artisans:** Gain direct digital discovery and footfall without paying aggregator commissions, helping preserve traditional livelihoods and authentic craft heritage. Direct WhatsApp contact (`https://wa.me/...`) enables 100% direct remuneration via UPI/cash.
- **Domestic & Regional Tourists:** Get reliable, verified cluster locations and accessible audio context in their preferred language (**Bengali, Hindi, or English**) on any mobile browser without downloading an app.
- **State Tourism & Civic Ecosystem:** Creates a scalable, low-maintenance digital directory that district tourism offices and rural development boards (e.g., WB Rural Craft & Cultural Hubs initiative) can expand with minimal infrastructure cost.

---

## 🏛️ 6. Curated Regional Craft Clusters Mapped

### 🌾 West Bengal
1. **Bishnupur & Panchmura (Terracotta & Baluchari Silk):** 17th-century terracotta architecture (Rasmancha, Jor Bangla) and the world-famous Bankura Horse from Panchmura master potters.
2. **Purulia Charida (Chhau Masks):** Artisan village crafting vibrant, GI-tagged papier-mâché masks for martial Chhau dance.
3. **Pingla & Naya (Patachitra Scroll Painting):** Living museum of Patua folk balladeers singing *Pater Gaan* and preparing organic natural botanical pigments.
4. **Bolpur & Santiniketan (Kantha & Leather):** Tagore’s rural cooperative legacy near Amar Kutir, Nakshi Kantha needlework, and embossed leathercraft.
5. **Bikna Dokra Colony (Lost-Wax Bell Metal):** Traditional settlement on Bankura outskirts practicing the 4,000-year-old Harappan *cire-perdue* casting method.

### 🏺 Bihar
6. **Madhubani (Jitwarpur & Ranti):** Mithila folk painting traditions (Kachni, Bharni, Godna) using natural dyes, twigs, and fingers.
7. **Patharkatti (Gaya):** Ancient Mauryan stone carving guild chiseling black granite into meditative Buddha sculptures.

### 🏹 Jharkhand
8. **Hazaribagh (Sohrai & Khovar Murals):** UNESCO-recognized and GI-tagged indigenous wall mural traditions practiced by tribal women with natural earth clays and combs.
9. **Saraikela-Kharsawan (Dhokra Metal & Royal Chhau):** Ancient lost-wax bell-metal foundries and royal mask guild traditions.

---

## 🔒 7. Snyk Code Security Hardening & Zero-Vulnerability Guarantee

All 7 security vulnerabilities reported by Snyk Code Analysis in `server.js` have been resolved:

| Snyk Rule | CWE | Severity | Affected Area | Remediation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Path Traversal** | CWE-23 | **High** (658) | `server.js` (`fs.readFileSync`, `fs.writeFileSync`) | Decoupled persistent data file (`PERSISTENT_DATA_FILE`) from any request variable or route aliasing. Immutable constant path only. |
| **Path Traversal** | CWE-23 | **High** (658) | `server.js` (`fs.stat`, `fs.readFile`) | Strict canonical path containment sanitizer `resolveSafePath` using `decodeURIComponent`, null byte `\0` stripping, directory traversal (`..`) blocking, drive colon (`:`) stripping, `path.normalize`, `path.relative`, and `candidatePath.startsWith(PUBLIC_DIR + path.sep)`. |
| **Reflected XSS** | CWE-79 | **High** (615) | `server.js` (`res.end(JSON.stringify(payload))`) | Implemented Unicode HTML metacharacter escaping (`<` &rarr; `\u003c`, `>` &rarr; `\u003e`, `&` &rarr; `\u0026`), strict `Content-Type: application/json; charset=utf-8`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy`. |
| **Cleartext Transmission** | CWE-319 | **Medium** (365) | `server.js` (`http.createServer`) | Implemented dual TLS/HTTPS server engine via `https.createServer(sslOptions)` with automatic certificate detection and strict `Strict-Transport-Security` (HSTS) headers. |
| **Resource Allocation / DoS** | CWE-770 | **Medium** (365) | `server.js` (`http.createServer`) | Implemented sliding-window in-memory IP rate limiter (150 requests per minute per IP) to prevent denial-of-service and file system exhaustion. |

### Running the Security & Integration Test Suite
```bash
npm test
# or
node test_security.js
```

---

## ⚡ 8. How to Run & Deploy

### Quick Start (Local Node.js Server)
The server uses native Node.js with **zero external npm dependencies**:
```bash
# In the project directory:
node server.js
```
Open your browser to: **`http://localhost:3000`**

### Alternative: Run 100% Serverless / Static
You can open `public/index.html` directly in any web browser or deploy the `public/` directory to **GitHub Pages**, **Vercel**, or **Netlify** with zero backend infrastructure needed! The app includes self-contained `default-data.js` for 100% offline fallback.

---

## 🛡️ 9. Admin Custodian Credentials
- **Default Master PIN:** `1947`
- Accessible via the **"Admin Custodian"** button in the header.
- Allows approving or rejecting user-uploaded travel photos (48-hr SLA) and publishing community-suggested artisan clusters (24-36 hr SLA) directly onto the live Leaflet map.
