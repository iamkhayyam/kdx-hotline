// About — static window.

export function buildAbout() {
  const body = document.createElement("div");
  body.className = "about";
  body.innerHTML = `
    <div class="about-logo">KDX</div>
    <div class="about-ver">client 0.1 · protocol v1</div>
    <p class="about-lead">A modern, from-scratch Rust rebuild of KDX — an early-2000s
      Hotline-style chat and file-sharing system.</p>
    <ul class="about-facts">
      <li>TLS 1.3 transport · trust-on-first-use certificate pinning</li>
      <li>Argon2id credentials · challenge-response login (password never sent)</li>
      <li>20-byte framed binary protocol · chunk-bitmap resumable transfers</li>
    </ul>
    <p class="about-manifesto">Not your corporate chat app. Digital freedom,
      delivered over port 10700.</p>
    <p class="about-foot">Rust · Tauri · rustls · sqlx</p>
  `;
  return { body };
}
