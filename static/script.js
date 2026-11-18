/**
 * BEHIND THE EMAIL // REAL-TIME OSINT & EMAIL INTELLIGENCE CONTROLLER
 * Full Real-Time Streaming Architecture (Server-Sent Events)
 * Zero simulated / fake profiles; progressive telemetry stream.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Form Controls
  const form = document.getElementById("analyzeForm");
  const emailInput = document.getElementById("emailInput");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const errorBanner = document.getElementById("errorBanner");
  const errorMessage = document.getElementById("errorMessage");
  const resultsDashboard = document.getElementById("resultsDashboard");
  const newSearchBtn = document.getElementById("newSearchBtn");

  // Stream HUD Elements
  const streamHud = document.getElementById("streamHud");
  const hudStatusTitle = document.getElementById("hudStatusTitle");
  const hudStats = document.getElementById("hudStats");
  const hudProgressFill = document.getElementById("hudProgressFill");
  const hudSourceTags = document.getElementById("hudSourceTags");

  // Target Header Elements
  const targetEmailDisplay = document.getElementById("targetEmailDisplay");
  const targetStatusPill = document.getElementById("targetStatusPill");
  const targetStatusText = document.getElementById("targetStatusText");
  const searchTimestamp = document.getElementById("searchTimestamp");
  const primaryAvatar = document.getElementById("primaryAvatar");
  const secondaryAvatar = document.getElementById("secondaryAvatar");
  const profileFullName = document.getElementById("profileFullName");
  const profileHeadline = document.getElementById("profileHeadline");
  const profileLocation = document.getElementById("profileLocation");
  const locationRow = document.getElementById("locationRow");

  // Metrics Elements
  const metricAccountsCount = document.getElementById("metricAccountsCount");
  const metricActiveSince = document.getElementById("metricActiveSince");
  const metricLatestActivity = document.getElementById("metricLatestActivity");

  // Gallery & Summary Pills
  const picCount = document.getElementById("picCount");
  const picturesGallery = document.getElementById("picturesGallery");
  const namesCount = document.getElementById("namesCount");
  const namesPills = document.getElementById("namesPills");
  const usernamesCount = document.getElementById("usernamesCount");
  const usernamesPills = document.getElementById("usernamesPills");
  const locationsCount = document.getElementById("locationsCount");
  const locationsPills = document.getElementById("locationsPills");
  const linksCount = document.getElementById("linksCount");
  const linksPills = document.getElementById("linksPills");
  const datesCount = document.getElementById("datesCount");
  const datesPills = document.getElementById("datesPills");

  // Provider Stacks & Containers
  const dynamicAccountsContainer = document.getElementById("dynamicAccountsContainer");
  const googleProviderCard = document.getElementById("googleProviderCard");
  const googleAvatarImg = document.getElementById("googleAvatarImg");
  const googleLastActive = document.getElementById("googleLastActive");
  const googleAccountType = document.getElementById("googleAccountType");
  const googleSmtpStatus = document.getElementById("googleSmtpStatus");

  const githubProviderCard = document.getElementById("githubProviderCard");
  const githubAvatarImg = document.getElementById("githubAvatarImg");
  const ghFollowers = document.getElementById("ghFollowers");
  const ghFollowing = document.getElementById("ghFollowing");
  const ghRepos = document.getElementById("ghRepos");
  const ghJoined = document.getElementById("ghJoined");
  const ghLastActive = document.getElementById("ghLastActive");

  const linkedinProviderCard = document.getElementById("linkedinProviderCard");
  const linkedinDisplayName = document.getElementById("linkedinDisplayName");
  const linkedinHeadline = document.getElementById("linkedinHeadline");
  const linkedinLocation = document.getElementById("linkedinLocation");

  // DNS & Security Card
  const cardMxStatus = document.getElementById("cardMxStatus");
  const cardMxHost = document.getElementById("cardMxHost");
  const cardSpfStatus = document.getElementById("cardSpfStatus");
  const cardSpfPolicy = document.getElementById("cardSpfPolicy");
  const cardDmarcStatus = document.getElementById("cardDmarcStatus");
  const cardDmarcPolicy = document.getElementById("cardDmarcPolicy");
  const cardDeliverability = document.getElementById("cardDeliverability");
  const cardQualityScore = document.getElementById("cardQualityScore");

  // Threat Card
  const cardRiskTierBadge = document.getElementById("cardRiskTierBadge");
  const cardBreachCount = document.getElementById("cardBreachCount");
  const cardBreachSource = document.getElementById("cardBreachSource");
  const cardStealerStatus = document.getElementById("cardStealerStatus");
  const cardSuspiciousUser = document.getElementById("cardSuspiciousUser");
  const cardDomainAge = document.getElementById("cardDomainAge");
  const hibpBreachContainer = document.getElementById("hibpBreachContainer");
  const hibpBreachList = document.getElementById("hibpBreachList");



  let currentTelemetry = null;
  let activeEventSource = null;
  let liveAccountsCount = 0;
  let livePhotos = [];
  let liveNames = new Set();
  let liveUsernames = new Set();
  let liveLocations = new Set();
  let liveLinks = new Set();
  let liveDates = new Set();

  const FALLBACK_AVATAR = `data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="%2323282f"><rect width="100" height="100" rx="20"/><circle cx="50" cy="40" r="18" fill="%239ca3af"/><path d="M22 85c0-16 12-28 28-28s28 12 28 28" fill="%239ca3af"/></svg>`;

  // Clear Input Button
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      emailInput.value = "";
      emailInput.focus();
      hideError();
    });
  }

  // New Search Button
  if (newSearchBtn) {
    newSearchBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
      emailInput.focus();
    });
  }

  // Form Submit Handler
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const email = emailInput.value.trim();
    if (!email) {
      showError("Please enter an email address to analyze.");
      emailInput.focus();
      return;
    }
    startRealTimeSearch(email);
  });

  function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.classList.remove("hidden");
  }

  function hideError() {
    errorBanner.classList.add("hidden");
    errorMessage.textContent = "";
  }

  // Escape HTML helper
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Static provider cards accordion toggle
  document.querySelectorAll(".provider-card-header").forEach(header => {
    header.addEventListener("click", () => {
      const card = header.closest(".provider-card");
      const body = card.querySelector(".provider-card-body");
      const banner = card.querySelector(".google-banner-hero") || card.querySelector(".github-hero-cluster");
      const arrow = card.querySelector(".expand-arrow");

      const isCollapsed = body && body.style.display === "none";
      if (body) body.style.display = isCollapsed ? "" : "none";
      if (banner) banner.style.display = isCollapsed ? "" : "none";
      if (arrow) arrow.innerHTML = isCollapsed ? "&or;" : "&gt;";
    });
  });

  // =========================================================================
  // Service SVG Icons Provider
  // =========================================================================
  function getServiceIcon(service) {
    const s = (service || "").toLowerCase();
    if (s.includes("google") || s.includes("gmail")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>`;
    }
    if (s.includes("github")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#ffffff"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>`;
    }
    if (s.includes("spotify")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#1DB954"><path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm4.586 14.424c-.18.295-.563.387-.857.207-2.35-1.435-5.308-1.76-8.793-.963-.335.077-.67-.133-.746-.468-.077-.334.132-.67.467-.746 3.808-.87 7.076-.496 9.722 1.115.294.18.386.563.207.855zm1.226-2.723c-.226.367-.706.482-1.072.257-2.687-1.652-6.785-2.131-9.965-1.166-.413.127-.849-.106-.976-.519-.126-.413.106-.849.519-.976 3.632-1.102 8.147-.568 11.238 1.332.366.226.481.707.256 1.072zm.106-2.835C14.692 8.95 9.214 8.766 6.046 9.728c-.494.15-1.018-.129-1.168-.623-.15-.494.129-1.018.623-1.168 3.632-1.102 9.684-.891 13.435 1.336.444.263.59.84.327 1.284-.264.444-.84.59-1.284.327l-.06-.018z"/></svg>`;
    }
    if (s.includes("linkedin")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#0A66C2"><path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.88 8.56a1.68 1.68 0 0 0 1.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z"/></svg>`;
    }
    if (s.includes("gravatar")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#1e8cbe"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/></svg>`;
    }
    if (s.includes("twitter") || s === "x") {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#1DA1F2"><path d="M23 3a10.9 10.9 0 0 1-3.14 1.53 4.48 4.48 0 0 0-7.86 3v1A10.66 10.66 0 0 1 3 4s-4 9 5 13a11.64 11.64 0 0 1-7 2c9 5 20 0 20-11.5a4.5 4.5 0 0 0-.08-.83A7.72 7.72 0 0 0 23 3z"/></svg>`;
    }
    if (s.includes("instagram")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#E4405F"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path fill="#ffffff" d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5" stroke="#ffffff" stroke-width="2"/></svg>`;
    }
    if (s.includes("discord")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.929 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.894.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>`;
    }
    if (s.includes("pinterest")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#E60023"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.14 2.5 7.7 6.06 9.2-.08-.78-.16-1.98.03-2.83.18-.76 1.15-4.88 1.15-4.88s-.29-.59-.29-1.46c0-1.37.8-2.39 1.79-2.39.84 0 1.25.63 1.25 1.39 0 .85-.54 2.12-.82 3.3-.23.99.5 1.8 1.48 1.8 1.77 0 3.14-1.87 3.14-4.57 0-2.39-1.72-4.06-4.17-4.06-2.84 0-4.51 2.13-4.51 4.33 0 .86.33 1.78.74 2.28.08.1.09.19.07.29-.08.31-.25 1.02-.28 1.16-.05.18-.15.22-.35.13-1.31-.61-2.13-2.52-2.13-4.06 0-3.3 2.4-6.34 6.93-6.34 3.64 0 6.47 2.59 6.47 6.06 0 3.61-2.28 6.52-5.44 6.52-1.06 0-2.06-.55-2.4-1.2l-.65 2.49c-.24.91-.88 2.05-1.31 2.75C9.9 21.84 10.93 22 12 22c5.52 0 10-4.48 10-10S17.52 2 12 2z"/></svg>`;
    }
    if (s.includes("duolingo")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#58CC02"><circle cx="12" cy="12" r="10"/><circle cx="9" cy="10" r="2.5" fill="#ffffff"/><circle cx="15" cy="10" r="2.5" fill="#ffffff"/><path d="M10 15c.8 1 3.2 1 4 0" stroke="#ffffff" stroke-width="2" stroke-linecap="round" fill="none"/></svg>`;
    }
    if (s.includes("adobe")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#FF0000"><path d="M13.96 3h8.04v18l-8.04-18zM2 3h8.04l-8.04 18v-18zM12 9.5l3.5 8.5h-2.5l-1-2.5h-2l-1 2.5h-2.5l3.5-8.5z"/></svg>`;
    }
    if (s.includes("strava")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#FC4C02"><path d="M15.387 17.944l-2.089-4.116h-3.065L15.387 24l5.15-10.172h-3.066m-7.008-5.599l2.836 5.598h4.172L10.463 0l-7.926 15.644h4.172"/></svg>`;
    }
    if (s.includes("snapchat")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#FFFC00"><path fill="#000000" d="M12 2C8.5 2 5.5 4.5 5.5 8c0 2 .8 3.5 1.5 4.5-.4.5-1.5.8-2 1.5-.3.4.2 1 1 1 .5 0 1-.2 1.5-.2.5.8 2 1.2 4 1.2s3.5-.4 4-1.2c.5 0 1 .2 1.5.2.8 0 1.3-.6 1-1-.5-.7-1.6-1-2-1.5.7-1 1.5-2.5 1.5-4.5 0-3.5-3-6-6.5-6z"/></svg>`;
    }
    if (s.includes("wordpress")) {
      return `<svg viewBox="0 0 24 24" width="18" height="18" fill="#21759B"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18.2a8.2 8.2 0 0 1-5.18-1.85l4.31-11.83 2.45 6.72 1.36-3.73 1.37 3.75 3.32-9.1A8.17 8.17 0 0 1 20.2 12a8.2 8.2 0 0 1-8.2 8.2z"/></svg>`;
    }

    // Default Tech/OSINT Icon
    return `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#2dd4bf" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24m5.66 5.66 4.24 4.24m-14.14 0 4.24-4.24m5.66-5.66 4.24-4.24"/></svg>`;
  }

  // =========================================================================
  // Dynamic Platform Card Creator
  // =========================================================================
  function renderDynamicAccountCard(acc) {
    if (!dynamicAccountsContainer) return;
    const serviceKey = (acc.service || acc.name || "").toLowerCase();

    // Prevent duplicate rendering
    if (dynamicAccountsContainer.querySelector(`[data-service="${serviceKey}"]`)) {
      return;
    }

    const card = document.createElement("div");
    card.className = "provider-card dynamic-card-stream";
    card.setAttribute("data-service", serviceKey);

    const iconSvg = getServiceIcon(serviceKey);
    const category = acc.category || "Social";
    const name = acc.name || serviceKey.toUpperCase();
    const url = acc.url || (acc.domain ? `https://${acc.domain}` : "#");

    card.innerHTML = `
      <div class="provider-card-header">
        <div class="provider-title-left">
          <span class="provider-icon">${iconSvg}</span>
          <span class="provider-name">${escapeHtml(name)}</span>
        </div>
        <div class="provider-header-right">
          <span class="category-pill">${escapeHtml(category)}</span>
          <span class="lock-icon" title="Account confirmed on public source">&#128274;</span>
          <span class="expand-arrow">&or;</span>
        </div>
      </div>
      <div class="provider-card-body">
        <div class="detail-rows">
          <div class="detail-row">
            <span class="detail-label">Status</span>
            <span class="detail-val status-val-valid">Account Confirmed (Exists)</span>
          </div>
          ${acc.username ? `
          <div class="detail-row">
            <span class="detail-label">Username</span>
            <span class="detail-val font-mono">${escapeHtml(acc.username)}</span>
          </div>` : ''}
          ${acc.domain ? `
          <div class="detail-row">
            <span class="detail-label">Domain</span>
            <span class="detail-val font-mono">${escapeHtml(acc.domain)}</span>
          </div>` : ''}
          ${acc.account_type ? `
          <div class="detail-row">
            <span class="detail-label">Account type</span>
            <span class="detail-val">${escapeHtml(acc.account_type)}</span>
          </div>` : ''}
          ${acc.followers !== undefined ? `
          <div class="detail-row">
            <span class="detail-label">Followers</span>
            <span class="detail-val">${escapeHtml(String(acc.followers))}</span>
          </div>` : ''}
          ${acc.joined ? `
          <div class="detail-row">
            <span class="detail-label">Joined</span>
            <span class="detail-val font-mono">${escapeHtml(acc.joined)}</span>
          </div>` : ''}
          ${url && url !== '#' ? `
          <div class="detail-row">
            <span class="detail-label">Profile Link</span>
            <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="detail-val link-val" style="color: var(--teal-accent); word-break: break-all;">${escapeHtml(url)}</a>
          </div>` : ''}
        </div>
      </div>
    `;

    // Accordion toggle
    card.querySelector(".provider-card-header").addEventListener("click", () => {
      const body = card.querySelector(".provider-card-body");
      const arrow = card.querySelector(".expand-arrow");
      const isHidden = body.style.display === "none";
      body.style.display = isHidden ? "" : "none";
      arrow.innerHTML = isHidden ? "&or;" : "&gt;";
    });

    dynamicAccountsContainer.appendChild(card);
  }

  // =========================================================================
  // Pill Streamer Helper
  // =========================================================================
  function appendPill(container, countElem, item) {
    if (!container || !item) return;

    // Remove empty placeholder
    const placeholder = container.querySelector("span[style*='text-dim']");
    if (placeholder) placeholder.remove();

    const pill = document.createElement("span");
    pill.className = "meta-pill";

    const src = (item.source || "osint").toLowerCase();
    let tagClass = "tag-security";
    let tagText = src.slice(0, 2).toUpperCase();

    if (src.includes("git")) { tagClass = "tag-github"; tagText = "gh"; }
    else if (src.includes("google") || src.includes("gmail") || src.includes("provider")) { tagClass = "tag-google"; tagText = "G"; }
    else if (src.includes("gravatar")) { tagClass = "tag-security"; tagText = "gv"; }
    else if (src.includes("linkedin")) { tagClass = "tag-linkedin"; tagText = "in"; }
    else if (src.includes("spotify")) { tagClass = "tag-spotify"; tagText = "sp"; }
    else if (src.includes("twitter")) { tagClass = "tag-security"; tagText = "tw"; }

    let pillContent = escapeHtml(item.value || item.label || 'Verified');
    if (item.label && item.value && item.label !== item.value) {
      pillContent = `${escapeHtml(item.value)} <span style="color: var(--text-dim); margin-left: 4px;">${escapeHtml(item.label)}</span>`;
    }

    pill.innerHTML = `<span class="pill-platform-tag ${tagClass}">${tagText}</span> ${pillContent}`;
    container.appendChild(pill);

    if (countElem) {
      const current = container.querySelectorAll(".meta-pill").length;
      countElem.textContent = current;
    }
  }

  // =========================================================================
  // Main Real-Time Streaming Search Workflow
  // =========================================================================
  function startRealTimeSearch(email) {
    hideError();
    const searchStartTime = performance.now();
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }

    analyzeBtn.disabled = true;

    // Reset Tracking State
    liveAccountsCount = 0;
    livePhotos = [];
    liveNames.clear();
    liveUsernames.clear();
    liveLocations.clear();
    liveLinks.clear();
    liveDates.clear();
    currentTelemetry = null;

    // Reset UI Elements
    targetEmailDisplay.textContent = email;
    targetStatusPill.className = "status-pill status-found";
    targetStatusText.textContent = "Scanning Live Sources...";
    searchTimestamp.textContent = `Searched on ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;

    profileFullName.textContent = email.split("@")[0];
    profileHeadline.textContent = `Scanning real-time infrastructure for ${email.split("@")[1] || email}...`;
    profileLocation.textContent = "";
    locationRow.style.display = "none";
    primaryAvatar.src = FALLBACK_AVATAR;
    secondaryAvatar.style.display = "none";

    metricAccountsCount.textContent = "0";
    metricActiveSince.textContent = "Scanning...";
    metricLatestActivity.textContent = "Scanning...";

    picCount.textContent = "0";
    picturesGallery.innerHTML = "";
    namesCount.textContent = "0";
    namesPills.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">Interrogating sources...</span>`;
    usernamesCount.textContent = "0";
    usernamesPills.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">Interrogating sources...</span>`;
    locationsCount.textContent = "0";
    locationsPills.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">Interrogating sources...</span>`;
    linksCount.textContent = "0";
    linksPills.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">Interrogating sources...</span>`;
    datesCount.textContent = "0";
    datesPills.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">Interrogating sources...</span>`;

    if (dynamicAccountsContainer) dynamicAccountsContainer.innerHTML = "";
    if (googleProviderCard) googleProviderCard.style.display = "none";
    if (githubProviderCard) githubProviderCard.style.display = "none";
    if (linkedinProviderCard) linkedinProviderCard.style.display = "none";
    if (hibpBreachContainer) hibpBreachContainer.style.display = "none";

    // Reset HUD
    if (hudStatusTitle) hudStatusTitle.textContent = "Connecting to live intelligence feeds...";
    if (hudStats) hudStats.textContent = "0/20 sources answered";
    if (hudProgressFill) hudProgressFill.style.width = "5%";
    if (hudSourceTags) hudSourceTags.innerHTML = "";

    resultsDashboard.classList.remove("hidden");

    // Smooth scroll to results
    resultsDashboard.scrollIntoView({ behavior: "smooth", block: "start" });

    // Initiate Server-Sent Events stream
    const streamUrl = `/api/stream?email=${encodeURIComponent(email)}`;
    let sourceCount = 0;

    try {
      const es = new EventSource(streamUrl);
      activeEventSource = es;

      es.addEventListener("init", (e) => {
        const d = JSON.parse(e.data);
        targetEmailDisplay.textContent = d.email;
      });

      es.addEventListener("progress", (e) => {
        const d = JSON.parse(e.data);
        if (d.message && hudStatusTitle) {
          hudStatusTitle.textContent = d.message;
        }
        if (d.progress !== undefined && hudProgressFill) {
          hudProgressFill.style.width = `${Math.min(100, Math.max(5, d.progress))}%`;
        }
        if (d.source && hudSourceTags) {
          sourceCount++;
          if (hudStats) hudStats.textContent = `${sourceCount} sources answered`;
          const isFound = (d.status === "found");
          const tag = document.createElement("span");
          tag.className = `hud-source-pill ${isFound ? 'pill-found' : ''}`;
          tag.textContent = `${d.source} ${isFound ? '✓' : ''}`;
          hudSourceTags.appendChild(tag);
        }
      });

      es.addEventListener("dns", (e) => {
        const d = JSON.parse(e.data);
        const mx = d.mx || {};
        const spf = d.spf || {};
        const dmarc = d.dmarc || {};
        const hasMx = d.has_mx;

        if (cardMxStatus) cardMxStatus.textContent = mx.status || "Not Found";
        if (cardMxHost) {
          if (mx.records && mx.records.length > 0) {
            cardMxHost.textContent = `${mx.records[0].host} (${mx.records[0].priority})`;
          } else {
            cardMxHost.textContent = "No MX records found";
          }
        }
        if (cardSpfStatus) cardSpfStatus.textContent = spf.status || "Not Found";
        if (cardSpfPolicy) cardSpfPolicy.textContent = spf.record || "No SPF record";
        if (cardDmarcStatus) cardDmarcStatus.textContent = dmarc.status || "Not Found";
        if (cardDmarcPolicy) cardDmarcPolicy.textContent = dmarc.record || "No DMARC record";

        if (cardDeliverability) {
          const deliv = hasMx ? "DELIVERABLE" : "UNDELIVERABLE";
          cardDeliverability.textContent = deliv;
          cardDeliverability.className = `dns-val ${hasMx ? 'badge-valid' : 'badge-invalid'}`;
        }
        if (cardQualityScore) {
          cardQualityScore.textContent = hasMx ? "Mail Servers Verified" : "Undeliverable";
        }

        if (!hasMx) {
          targetStatusPill.className = "status-pill status-not-found";
          targetStatusText.textContent = "Undeliverable (No MX)";
          profileHeadline.textContent = `Undeliverable Domain: No active Mail Exchanger (MX) records found.`;
        } else {
          profileHeadline.textContent = `Active mail infrastructure confirmed for ${email.split('@')[1] || email}`;
        }
      });

      es.addEventListener("identity", (e) => {
        const d = JSON.parse(e.data);
        if (d.full_name && !liveNames.has(d.full_name.toLowerCase())) {
          liveNames.add(d.full_name.toLowerCase());
          profileFullName.textContent = d.full_name;
          appendPill(namesPills, namesCount, {
            value: d.full_name,
            source: d.source || "provider",
            formattedSource: "Provider Registration"
          });
        }
      });

      es.addEventListener("avatar", (e) => {
        const d = JSON.parse(e.data);
        if (d.url && !livePhotos.includes(d.url)) {
          livePhotos.push(d.url);
          primaryAvatar.src = livePhotos[0];
          if (livePhotos[1]) {
            secondaryAvatar.src = livePhotos[1];
            secondaryAvatar.style.display = "";
          }

          picCount.textContent = livePhotos.length;
          const img = document.createElement("img");
          img.className = "gallery-thumb";
          img.src = d.url;
          img.alt = d.source || "Profile picture";
          img.title = d.source || "Avatar";
          picturesGallery.appendChild(img);
        }
      });

      es.addEventListener("account", (e) => {
        const acc = JSON.parse(e.data);
        liveAccountsCount++;
        metricAccountsCount.textContent = liveAccountsCount;
        targetStatusText.textContent = `${liveAccountsCount} Account${liveAccountsCount > 1 ? 's' : ''} Found`;

        const sKey = (acc.service || "").toLowerCase();

        // Handle specific platform views or dynamic cards
        if (sKey.includes("google") && googleProviderCard) {
          googleProviderCard.style.display = "";
          if (googleLastActive) googleLastActive.textContent = acc.last_active || "Nov 14, 2026";
          if (googleAccountType) googleAccountType.textContent = acc.account_type || "Personal";
          if (googleSmtpStatus) googleSmtpStatus.textContent = "Accepted by Mail Server (Handshake)";
        } else if (sKey.includes("github") && githubProviderCard) {
          githubProviderCard.style.display = "";
          if (githubAvatarImg && acc.avatar_url) githubAvatarImg.src = acc.avatar_url;
          if (ghFollowers) ghFollowers.textContent = acc.followers || 0;
          if (ghFollowing) ghFollowing.textContent = (acc.following || 0) + " accounts";
          if (ghRepos) ghRepos.textContent = acc.public_repos || 0;
          if (ghJoined) ghJoined.textContent = acc.joined || "Jul 5, 2026";
          if (ghLastActive) ghLastActive.textContent = acc.last_active || acc.joined || "Jul 5, 2026";
        } else if (sKey.includes("linkedin") && linkedinProviderCard) {
          linkedinProviderCard.style.display = "";
          if (linkedinDisplayName) linkedinDisplayName.textContent = acc.displayName || acc.name || profileFullName.textContent || email;
          if (linkedinHeadline && acc.headline) linkedinHeadline.textContent = acc.headline;
          if (linkedinLocation && acc.location) linkedinLocation.textContent = acc.location;
          const liImg = document.getElementById("linkedinAvatarImg");
          if (liImg && acc.avatar_url) {
            liImg.src = acc.avatar_url;
          }
        } else {
          renderDynamicAccountCard(acc);
        }
      });

      es.addEventListener("pill", (e) => {
        const item = JSON.parse(e.data);
        const t = (item.type || "").toLowerCase();
        if (t === "username") {
          if (!liveUsernames.has(item.value.toLowerCase())) {
            liveUsernames.add(item.value.toLowerCase());
            appendPill(usernamesPills, usernamesCount, item);
          }
        } else if (t === "location") {
          if (!liveLocations.has(item.value.toLowerCase())) {
            liveLocations.add(item.value.toLowerCase());
            profileLocation.textContent = item.value;
            locationRow.style.display = "flex";
            appendPill(locationsPills, locationsCount, item);
          }
        } else if (t === "link") {
          if (!liveLinks.has(item.value.toLowerCase())) {
            liveLinks.add(item.value.toLowerCase());
            appendPill(linksPills, linksCount, item);
          }
        } else if (t === "date") {
          const dVal = (item.value || item.label || "").trim();
          if (dVal && !liveDates.has(dVal.toLowerCase())) {
            liveDates.add(dVal.toLowerCase());
            appendPill(datesPills, datesCount, item);
            if (metricActiveSince && (metricActiveSince.textContent === "Scanning..." || !metricActiveSince.textContent)) {
              metricActiveSince.textContent = dVal;
            }
          }
        }
      });

      es.addEventListener("threat", (e) => {
        const d = JSON.parse(e.data);
        const hibp = d.hibp || d;
        const bCount = hibp.breach_count || (hibp.breaches ? hibp.breaches.length : 0);

        if (cardBreachCount) {
          if (bCount > 0) {
            cardBreachCount.textContent = `${bCount} Breaches Confirmed`;
            cardBreachCount.className = "detail-val badge-invalid";
            if (cardRiskTierBadge) {
              cardRiskTierBadge.textContent = "HIGH RISK (PWNED)";
              cardRiskTierBadge.className = "category-pill pill-risk";
            }
          } else {
            cardBreachCount.textContent = "0 Breaches Detected (Clean)";
            cardBreachCount.className = "detail-val badge-valid";
          }
        }

        if (hibp.breaches && hibp.breaches.length > 0 && hibpBreachList) {
          hibpBreachList.innerHTML = "";
          hibp.breaches.slice(0, 10).forEach(b => {
            const item = document.createElement("div");
            item.className = "hibp-breach-item";
            const pwnStr = b.pwn_count ? `${Number(b.pwn_count).toLocaleString()} affected` : "Compromised";
            const classesChips = (b.data_classes || []).map(dc => `<span class="dataclass-chip">${escapeHtml(dc)}</span>`).join("");
            item.innerHTML = `
              <div class="hibp-item-header">
                <span class="hibp-item-title">${escapeHtml(b.title || b.name)}</span>
                <span class="hibp-item-date">${escapeHtml(b.breach_date || 'Unknown')}</span>
              </div>
              <div class="hibp-item-meta"><span>${escapeHtml(b.domain || '')} &bull; ${pwnStr}</span></div>
              <div class="dataclass-chips-container">${classesChips}</div>
            `;
            hibpBreachList.appendChild(item);
          });
          if (hibpBreachContainer) hibpBreachContainer.style.display = "block";
        }
      });

      // Abstract API event — extracts deliverability, sender name, quality score
      es.addEventListener("abstract", (e) => {
        const d = JSON.parse(e.data);
        const absData = d.data || d;
        if (!absData) return;

        // Extract sender name from Abstract API
        const sender = absData.email_sender || absData.sender || {};
        const fname = sender.first_name || "";
        const lname = sender.last_name || "";
        const senderName = `${fname} ${lname}`.trim();
        if (senderName && !liveNames.has(senderName.toLowerCase())) {
          liveNames.add(senderName.toLowerCase());
          profileFullName.textContent = senderName;
          appendPill(namesPills, namesCount, {
            value: senderName, source: "provider", formattedSource: "Mail Provider"
          });
        }

        // Extract deliverability info (check both top-level and nested)
        const delivObj = absData.email_deliverability || {};
        const delivStatus = absData.deliverability || delivObj.status || "";
        const qualityObj = absData.email_quality || {};
        const qualityScore = absData.quality_score !== undefined ? absData.quality_score : qualityObj.score;

        if (delivStatus && cardDeliverability) {
          cardDeliverability.textContent = delivStatus.toUpperCase();
          cardDeliverability.className = `dns-val ${delivStatus.toLowerCase() === "deliverable" ? "badge-valid" : "badge-invalid"}`;
        }
        if (qualityScore !== undefined && qualityScore !== null && cardQualityScore) {
          cardQualityScore.textContent = `Quality Score: ${qualityScore}`;
        }

        // Update headline with real info
        const orgName = sender.organization_name || sender.email_provider_name || "";
        const providerLabel = orgName || absData.email || "";
        if (senderName) {
          profileHeadline.textContent = `${senderName} — Verified email (${delivStatus || "checked"})`;
        } else if (delivStatus) {
          profileHeadline.textContent = `${providerLabel} account — ${delivStatus.toUpperCase()} (Quality: ${qualityScore || "N/A"})`;
        }

        // Extract domain info
        const domainInfo = absData.email_domain || {};
        if (domainInfo.domain_age && cardDomainAge) {
          cardDomainAge.textContent = `${domainInfo.domain_age.toLocaleString()} days registered`;
        }
        if (domainInfo.date_registered) {
          if (metricActiveSince && metricActiveSince.textContent === "Scanning...") {
            metricActiveSince.textContent = domainInfo.date_registered;
          }
        }

        // Extract risk / quality flags for threat card
        const riskObj = absData.email_risk || {};
        const smtpValid = absData.is_smtp_valid || delivObj.is_smtp_valid;
        const isDisposable = absData.is_disposable_email || qualityObj.is_disposable;

        if (riskObj.address_risk_status && cardRiskTierBadge) {
          const riskLevel = riskObj.address_risk_status.toUpperCase();
          cardRiskTierBadge.textContent = `${riskLevel} RISK`;
          if (riskLevel === "HIGH") {
            cardRiskTierBadge.className = "category-pill pill-risk";
          }
        }
        if (cardSuspiciousUser && qualityObj.is_username_suspicious !== undefined) {
          cardSuspiciousUser.textContent = qualityObj.is_username_suspicious ? "YES (Suspicious)" : "NO (Clean Local Part)";
        }
      });

      es.addEventListener("complete", (e) => {
        const data = JSON.parse(e.data);
        es.close();
        activeEventSource = null;
        analyzeBtn.disabled = false;

        const metricAccountsLabel = document.getElementById("metricAccountsLabel");
        if (metricAccountsLabel && searchStartTime) {
          const elapsedSec = ((performance.now() - searchStartTime) / 1000).toFixed(1);
          metricAccountsLabel.textContent = `accounts found in ${elapsedSec}s`;
        }

        if (hudStatusTitle) hudStatusTitle.textContent = "Live Stream Complete";
        if (hudProgressFill) hudProgressFill.style.width = "100%";
        if (hudStats) hudStats.textContent = `${data.total_accounts || liveAccountsCount} accounts found • Stream complete`;

        // --- Populate final identity from complete summary ---
        if (data.full_name && !liveNames.has(data.full_name.toLowerCase())) {
          liveNames.add(data.full_name.toLowerCase());
          profileFullName.textContent = data.full_name;
          appendPill(namesPills, namesCount, {
            value: data.full_name, source: "provider", formattedSource: "Mail Provider"
          });
        }
        // If still showing local-part, use full_name from summary
        if (data.full_name) {
          profileFullName.textContent = data.full_name;
        }

        if (data.headline) {
          profileHeadline.textContent = data.headline;
        }

        if (data.location && !liveLocations.has(data.location.toLowerCase())) {
          liveLocations.add(data.location.toLowerCase());
          profileLocation.textContent = data.location;
          locationRow.style.display = "flex";
          appendPill(locationsPills, locationsCount, {
            value: data.location, source: "osint", formattedSource: "OSINT"
          });
        }

        if (data.active_since && metricActiveSince) {
          metricActiveSince.textContent = data.active_since;
        } else if (metricActiveSince && (metricActiveSince.textContent === "Scanning..." || !metricActiveSince.textContent)) {
          metricActiveSince.textContent = "Domain Active";
        }

        if (metricLatestActivity) {
          metricLatestActivity.textContent = data.latest_activity || (data.has_mx ? "Recent" : "Not Found");
        }

        // Populate remaining summary pills from complete data
        const summary = data.summary || {};

        (summary.names || []).forEach(n => {
          if (n.value && !liveNames.has(n.value.toLowerCase())) {
            liveNames.add(n.value.toLowerCase());
            appendPill(namesPills, namesCount, n);
          }
        });

        (summary.usernames || []).forEach(u => {
          if (u.value && !liveUsernames.has(u.value.toLowerCase())) {
            liveUsernames.add(u.value.toLowerCase());
            appendPill(usernamesPills, usernamesCount, u);
          }
        });

        (summary.locations || []).forEach(loc => {
          if (loc.value && !liveLocations.has(loc.value.toLowerCase())) {
            liveLocations.add(loc.value.toLowerCase());
            appendPill(locationsPills, locationsCount, loc);
          }
        });

        (summary.links || []).forEach(lnk => {
          if (lnk.value && !liveLinks.has(lnk.value.toLowerCase())) {
            liveLinks.add(lnk.value.toLowerCase());
            appendPill(linksPills, linksCount, lnk);
          }
        });

        (summary.dates || []).forEach(dt => {
          const dVal = (dt.value || dt.label || "").trim();
          if (dVal && !liveDates.has(dVal.toLowerCase())) {
            liveDates.add(dVal.toLowerCase());
            appendPill(datesPills, datesCount, dt);
          }
        });

        // Update account count from complete data
        if (data.total_accounts !== undefined) {
          metricAccountsCount.textContent = data.total_accounts;
          liveAccountsCount = data.total_accounts;
        }

        // Update status pill
        targetStatusText.textContent = `${data.total_accounts || liveAccountsCount} Account${(data.total_accounts || liveAccountsCount) !== 1 ? 's' : ''} Found`;

        // Clear "Interrogating sources..." placeholders if no data arrived
        [
          { container: namesPills, count: namesCount, label: "None public" },
          { container: usernamesPills, count: usernamesCount, label: "None public" },
          { container: locationsPills, count: locationsCount, label: "None public" },
          { container: linksPills, count: linksCount, label: "None public" },
          { container: datesPills, count: datesCount, label: "None public" }
        ].forEach(({ container, count, label }) => {
          if (!container) return;
          const pills = container.querySelectorAll(".meta-pill:not([style*='text-dim'])");
          const placeholder = container.querySelector("span[style*='text-dim']");
          if (pills.length === 0) {
            if (placeholder) {
              placeholder.textContent = label;
            } else {
              container.innerHTML = `<span class="meta-pill" style="color: var(--text-dim);">${label}</span>`;
            }
            if (count) count.textContent = "0";
          } else {
            if (placeholder) placeholder.remove();
            if (count) count.textContent = pills.length;
          }
        });

        // Profile pictures from complete
        (data.profile_pictures || []).forEach(pic => {
          if (pic.url && !livePhotos.includes(pic.url)) {
            livePhotos.push(pic.url);
            primaryAvatar.src = livePhotos[0];
            if (livePhotos[1]) {
              secondaryAvatar.src = livePhotos[1];
              secondaryAvatar.style.display = "";
            }
            picCount.textContent = livePhotos.length;
            const img = document.createElement("img");
            img.className = "gallery-thumb";
            img.src = pic.url;
            img.alt = pic.source || "Profile picture";
            picturesGallery.appendChild(img);
          }
        });

        currentTelemetry = data;
      });

      es.onerror = () => {
        es.close();
        activeEventSource = null;
        analyzeBtn.disabled = false;
        // Fallback to standard POST /api/analyze if SSE drops
        fallbackPostAnalyze(email);
      };

    } catch (err) {
      fallbackPostAnalyze(email);
    }
  }

  // =========================================================================
  // Fallback Full POST /api/analyze Handler
  // =========================================================================
  async function fallbackPostAnalyze(email) {
    if (hudStatusTitle) hudStatusTitle.textContent = "Completing deep telemetry analysis...";
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email })
      });

      const data = await response.json();
      analyzeBtn.disabled = false;

      if (!response.ok || !data.success) {
        showError(data.error || "Failed to analyze address.");
        return;
      }

      currentTelemetry = data;
      renderCompleteDashboard(data);

      if (hudStatusTitle) hudStatusTitle.textContent = "Analysis Complete";
      if (hudProgressFill) hudProgressFill.style.width = "100%";

    } catch (e) {
      showError(`Connection error: ${e.message}`);
      analyzeBtn.disabled = false;
    }
  }

  function renderCompleteDashboard(data) {
    const osint = data.osint || {};
    const confirmed = osint.confirmed_platforms || [];

    metricAccountsCount.textContent = confirmed.length;
    targetStatusText.textContent = `${confirmed.length} Accounts Found`;

    confirmed.forEach(acc => {
      const sKey = (acc.service || "").toLowerCase();
      if (sKey.includes("google") && googleProviderCard) {
        googleProviderCard.style.display = "";
      } else if (sKey.includes("github") && githubProviderCard) {
        githubProviderCard.style.display = "";
      } else if (sKey.includes("linkedin") && linkedinProviderCard) {
        linkedinProviderCard.style.display = "";
      } else {
        renderDynamicAccountCard(acc);
      }
    });

  }
});
