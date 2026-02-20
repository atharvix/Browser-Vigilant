<script>
  import "./app.css";
  import Shield from "./components/Shield.svelte";
  import History from "./components/History.svelte";
  import Blockchain from "./components/Blockchain.svelte";
  import Settings from "./components/Settings.svelte";

  let activeTab = "shield";

  const tabs = [
    { id: "shield", label: "Shield", icon: "🛡️" },
    { id: "history", label: "History", icon: "📋" },
    { id: "chain", label: "Ledger", icon: "⛓️" },
    { id: "settings", label: "Settings", icon: "⚙️" },
  ];
</script>

<div class="popup-root">
  <!-- Header -->
  <header class="header">
    <div class="logo">
      <div class="logo-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
            fill="url(#shieldGrad)"
            stroke="rgba(99,179,237,0.4)"
            stroke-width="0.5"
          />
          <path
            d="M9.5 12.5l2 2 4-4"
            stroke="#f0f4ff"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
          <defs>
            <linearGradient
              id="shieldGrad"
              x1="3"
              y1="2"
              x2="21"
              y2="23"
              gradientUnits="userSpaceOnUse"
            >
              <stop stop-color="#3b82f6" />
              <stop offset="1" stop-color="#1d4ed8" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="logo-text">
        <span class="logo-name">Browser Vigilant</span>
        <span class="logo-version">v1.0 · WASM Engine</span>
      </div>
    </div>
    <div class="status-badge active">
      <span class="status-dot"></span>
      Active
    </div>
  </header>

  <!-- Tabs -->
  <nav class="tabs">
    {#each tabs as tab}
      <button
        class="tab-btn {activeTab === tab.id ? 'active' : ''}"
        on:click={() => (activeTab = tab.id)}
      >
        <span>{tab.icon}</span>
        <span>{tab.label}</span>
      </button>
    {/each}
  </nav>

  <!-- Content -->
  <main class="content">
    {#if activeTab === "shield"}
      <Shield />
    {:else if activeTab === "history"}
      <History />
    {:else if activeTab === "chain"}
      <Blockchain />
    {:else if activeTab === "settings"}
      <Settings />
    {/if}
  </main>

  <!-- Footer -->
  <footer class="footer">
    <span class="footer-text"
      >100% On-Device · Zero Data Leaks · Rust WASM Core</span
    >
  </footer>
</div>

<style>
  .popup-root {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 500px;
    background: var(--bg-primary);
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    position: relative;
    overflow: hidden;
  }

  .header::after {
    content: "";
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(
      90deg,
      transparent,
      var(--border-glow),
      transparent
    );
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .logo-icon {
    width: 36px;
    height: 36px;
    background: linear-gradient(
      135deg,
      rgba(59, 130, 246, 0.2),
      rgba(29, 78, 216, 0.1)
    );
    border: 1px solid rgba(59, 130, 246, 0.3);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 12px rgba(59, 130, 246, 0.15);
  }

  .logo-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .logo-name {
    font-size: 13px;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: 0.02em;
  }

  .logo-version {
    font-size: 9px;
    font-family: var(--font-mono);
    color: var(--text-muted);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .status-badge {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 100px;
    border: 1px solid var(--accent-green);
    color: var(--accent-green);
    background: rgba(16, 185, 129, 0.08);
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent-green);
    box-shadow: 0 0 6px var(--accent-green);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
      transform: scale(1);
    }
    50% {
      opacity: 0.6;
      transform: scale(0.85);
    }
  }

  .tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    padding: 0 8px;
  }

  .tab-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    padding: 9px 4px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-family: var(--font-main);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s ease;
    letter-spacing: 0.02em;
    position: relative;
    bottom: -1px;
  }

  .tab-btn:hover {
    color: var(--text-secondary);
  }

  .tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .content {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    background: var(--bg-primary);
  }

  .footer {
    padding: 8px 16px;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  .footer-text {
    font-size: 9px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    letter-spacing: 0.04em;
    display: block;
    text-align: center;
  }
</style>
