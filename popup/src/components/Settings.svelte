<script>
    let protection = true;
    let notifications = true;
    let strictMode = false;
    let autoBlock = true;

    const version = "1.0.0";
    const engine = "Rust WASM v0.1.0";
</script>

<div class="settings-wrap">
    <div class="settings-group">
        <div class="group-label">Protection</div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Real-Time Shield</span>
                <span class="setting-desc"
                    >Actively scan every page you visit</span
                >
            </div>
            <label class="toggle">
                <input type="checkbox" bind:checked={protection} />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Auto-Block Threats</span>
                <span class="setting-desc"
                    >Immediately block detected phishing pages</span
                >
            </div>
            <label class="toggle">
                <input type="checkbox" bind:checked={autoBlock} />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Strict Mode</span>
                <span class="setting-desc"
                    >Block sites with any suspicious signals</span
                >
            </div>
            <label class="toggle">
                <input type="checkbox" bind:checked={strictMode} />
                <span class="toggle-track"></span>
            </label>
        </div>
    </div>

    <div class="settings-group">
        <div class="group-label">Alerts</div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Block Notifications</span>
                <span class="setting-desc"
                    >Show a badge when a threat is blocked</span
                >
            </div>
            <label class="toggle">
                <input type="checkbox" bind:checked={notifications} />
                <span class="toggle-track"></span>
            </label>
        </div>
    </div>

    <div class="settings-group info-group">
        <div class="group-label">About</div>
        <div class="about-grid">
            <div class="about-row">
                <span class="about-key">Version</span><span class="about-val"
                    >{version}</span
                >
            </div>
            <div class="about-row">
                <span class="about-key">Engine</span><span class="about-val"
                    >{engine}</span
                >
            </div>
            <div class="about-row">
                <span class="about-key">Privacy</span><span
                    class="about-val"
                    style="color:#10b981">100% On-Device</span
                >
            </div>
            <div class="about-row">
                <span class="about-key">Data Shared</span><span
                    class="about-val"
                    style="color:#10b981">None</span
                >
            </div>
        </div>
    </div>
</div>

<style>
    .settings-wrap {
        display: flex;
        flex-direction: column;
        gap: 14px;
    }

    .settings-group {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
    }

    .group-label {
        font-size: 9px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        padding: 10px 14px 6px;
        border-bottom: 1px solid var(--border);
    }

    .setting-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 11px 14px;
        border-bottom: 1px solid var(--border);
        gap: 12px;
        transition: background 0.15s;
    }
    .setting-row:last-child {
        border-bottom: none;
    }
    .setting-row:hover {
        background: var(--bg-card-hover);
    }

    .setting-info {
        display: flex;
        flex-direction: column;
        gap: 2px;
        flex: 1;
    }
    .setting-name {
        font-size: 12px;
        font-weight: 500;
        color: var(--text-primary);
    }
    .setting-desc {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }

    /* Toggle */
    .toggle {
        position: relative;
        cursor: pointer;
        flex-shrink: 0;
    }
    .toggle input {
        display: none;
    }
    .toggle-track {
        display: block;
        width: 34px;
        height: 18px;
        background: rgba(255, 255, 255, 0.08);
        border-radius: 100px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        position: relative;
        transition: all 0.2s ease;
    }
    .toggle-track::after {
        content: "";
        position: absolute;
        top: 2px;
        left: 2px;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: var(--text-muted);
        transition: all 0.2s ease;
    }
    .toggle input:checked + .toggle-track {
        background: rgba(59, 130, 246, 0.3);
        border-color: var(--accent);
    }
    .toggle input:checked + .toggle-track::after {
        transform: translateX(16px);
        background: var(--accent);
        box-shadow: 0 0 6px var(--accent);
    }

    /* About */
    .info-group {
    }
    .about-grid {
        padding: 6px 0;
    }
    .about-row {
        display: flex;
        justify-content: space-between;
        padding: 7px 14px;
        border-bottom: 1px solid var(--border);
    }
    .about-row:last-child {
        border-bottom: none;
    }
    .about-key {
        font-size: 10px;
        color: var(--text-muted);
    }
    .about-val {
        font-size: 10px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
    }
</style>
