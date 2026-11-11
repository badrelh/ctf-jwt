function getToken() {
    return localStorage.getItem("ctf_token") || "";
  }
  function setToken(t) {
    localStorage.setItem("ctf_token", t);
    renderToken();
  }
  function clearToken() {
    localStorage.removeItem("ctf_token");
    renderToken();
  }
  
  function renderToken() {
    const el = document.getElementById("tokenBox");
    if (!el) return;
    el.textContent = getToken() ? getToken() : "No token";
  }
  
  async function postJson(url, body, token = "") {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const r = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
    const txt = await r.text();
    let json;
    try { json = JSON.parse(txt); } catch { json = { raw: txt }; }
    return { status: r.status, json };
  }
  
  async function getJson(url, token = "") {
    const headers = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const r = await fetch(url, { method: "GET", headers });
    const txt = await r.text();
    let json;
    try { json = JSON.parse(txt); } catch { json = { raw: txt }; }
    return { status: r.status, json };
  }
  
  document.addEventListener("DOMContentLoaded", () => {
    renderToken();
  
    const btnClear = document.getElementById("btnClear");
    if (btnClear) btnClear.addEventListener("click", clearToken);
  
    const btnLogin = document.getElementById("btnLogin");
    if (btnLogin) {
      btnLogin.addEventListener("click", async () => {
        const u = document.getElementById("username")?.value || "";
        const p = document.getElementById("password")?.value || "";
        const out = document.getElementById("loginResult");
        const { status, json } = await postJson("/server/login", { username: u, password: p });
        if (out) out.textContent = JSON.stringify({ status, ...json }, null, 2);
        if (status === 200 && json.token) setToken(json.token);
      });
    }
  
    const btnMe = document.getElementById("btnMe");
    if (btnMe) {
      btnMe.addEventListener("click", async () => {
        const out = document.getElementById("meResult");
        const { status, json } = await getJson("/server/me", getToken());
        if (out) out.textContent = JSON.stringify({ status, ...json }, null, 2);
      });
    }
  
    const btnFetch = document.getElementById("btnFetch");
    if (btnFetch) {
      btnFetch.addEventListener("click", async () => {
        const url = document.getElementById("fetchUrl")?.value || "";
        const out = document.getElementById("fetchResult");
        const preview = document.getElementById("preview");
        if (preview) preview.innerHTML = "";
  
        const { status, json } = await postJson("/server/profile-image", { url }, getToken());
        if (out) out.textContent = JSON.stringify({ status, ...json }, null, 2);
  
        if (
          status === 200 &&
          json.url &&
          json.type &&
          json.type.startsWith("image/") &&
          preview
        ) {
          const img = document.createElement("img");
          img.src = json.url;
          img.alt = "Profile image";
          img.style.maxWidth = "300px";
          img.style.marginTop = "10px";
          preview.appendChild(img);
        }
        
      });
    }
  });
  