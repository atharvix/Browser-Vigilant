<script>
    import { onMount } from "svelte";

    // Simulated data — in real extension this comes from content.js via chrome.runtime.sendMessage
    let currentUrl = "https://www.google.com";
    let status = "safe"; // 'safe' | 'threat' | 'scanning'
    let scanMs = 2.4;
    let totalScanned = 138;
    let blockedToday = 3;

    // Threat DNA — 12 heuristic signals, each 0.0 → 1.0
    const signals = [
        { label: "URL Entropy", value: 0.08 },
        { label: "Subdomain Depth", value: 0.05 },
        { label: "HTTPS", value: 0.0 },
        { label: "IP in URL", value: 0.0 },
        { label: "Punycode", value: 0.0 },
        { label: "Brand Spoof", value: 0.12 },
        { label: "Suspicious TLD", value: 0.0 },
        { label: "Login Keyword", value: 0.0 },
        { label: "Hyphen Spam", value: 0.05 },
        { label: "Digit Ratio", value: 0.06 },
        { label: "Path Depth", value: 0.1 },
        { label: "Redirect Chain", value: 0.0 },
    ];

    const threatSignals = [
        { label: "URL Entropy", value: 0.82 },
        { label: "Subdomain Depth", value: 0.91 },
        { label: "HTTPS", value: 0.0 },
        { label: "IP in URL", value: 0.0 },
        { label: "Punycode", value: 0.0 },
        { label: "Brand Spoof", value: 0.94 },
        { label: "Suspicious TLD", value: 1.0 },
        { label: "Login Keyword", value: 1.0 },
        { label: "Hyphen Spam", value: 0.78 },
        { label: "Digit Ratio", value: 0.65 },
        { label: "Path Depth", value: 0.55 },
        { label: "Redirect Chain", value: 0.0 },
    ];

    let activeSignals = signals;

    function simulateThreat() {
        status = "scanning";
        currentUrl = "http://secure.login.verify.paypаl-update.xyz/account";
        setTimeout(() => {
            status = "threat";
            activeSignals = threatSignals;
        }, 800);
    }

    function simulateSafe() {
        status = "scanning";
        currentUrl = "https://www.google.com";
        setTimeout(() => {
            status = "safe";
            activeSignals = signals;
        }, 600);
    }

    function getBarColor(value) {
        if (value > 0.7) return "#ef4444";
        if (value > 0.4) return "#f59e0b";
        return "#10b981";
    }

    function getRiskScore(sigs) {
        const avg = sigs.reduce((a, s) => a + s.value, 0) / sigs.length;
        return Math.round(avg * 100);
    }

    $: riskScore = getRiskScore(activeSignals);
    $: topThreats = activeSignals
        .filter((s) => s.value > 0.5)
        .sort((a, b) => b.value - a.value);
</script>

<div class="shield-wrap">
    <!-- Current URL -->
    <div class="url-pill">
        <span class="url-icon">🔗</span>
        <span class="url-text"
            >{currentUrl.length > 38
                ? currentUrl.slice(0, 35) + "..."
                : currentUrl}</span
        >
    </div>

    <!-- Big status display -->
    <div class="status-block {status}">
        {#if status === "scanning"}
            <div class="scan-ring">
                <div class="scan-inner">
                    <span class="scan-icon">⚡</span>
                </div>
            </div>
            <p class="status-label">Analyzing...</p>
            <p class="status-sub">WASM engine running</p>
        {:else if status === "safe"}
            <div class="status-icon-circle safe">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
                    <path
                        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
                        fill="rgba(16,185,129,0.2)"
                        stroke="#10b981"
                        stroke-width="1.5"
                    />
                    <path
                        d="M9 12.5l2 2 4-4"
                        stroke="#10b981"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            </div>
            <p class="status-label">Site is Safe</p>
            <p class="status-sub">Scanned in {scanMs}ms · Engine: Rust WASM</p>
        {:else if status === "threat"}
            <div class="status-icon-circle threat">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
                    <path
                        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
                        fill="rgba(239,68,68,0.2)"
                        stroke="#ef4444"
                        stroke-width="1.5"
                    />
                    <path
                        d="M12 8v4M12 15h0"
                        stroke="#ef4444"
                        stroke-width="2"
                        stroke-linecap="round"
                    />
                </svg>
            </div>
            <p class="status-label">Threat Blocked</p>
            <p class="status-sub">Phishing attempt detected · Access denied</p>
        {/if}
    </div>

    <!-- Risk Score -->
    {#if status !== "scanning"}
        <div class="risk-row">
            <div class="risk-card">
                <span class="risk-num {riskScore > 50 ? 'danger' : 'ok'}"
                    >{riskScore}</span
                >
                <span class="risk-label">Risk Score</span>
            </div>
            <div class="risk-card">
                <span class="risk-num ok">{scanMs}ms</span>
                <span class="risk-label">Scan Time</span>
            </div>
            <div class="risk-card">
                <span class="risk-num">{blockedToday}</span>
                <span class="risk-label">Blocked Today</span>
            </div>
            <div class="risk-card">
                <span class="risk-num">{totalScanned}</span>
                <span class="risk-label">Total Scanned</span>
            </div>
        </div>

        <!-- Threat DNA Visualizer -->
        <div class="dna-section">
            <div class="section-header">
                <span class="section-title">Threat DNA</span>
                <span class="section-badge">Explainable AI</span>
            </div>
            <p class="section-sub">
                Signal analysis from {activeSignals.length} heuristic detectors
            </p>
            <div class="dna-bars">
                {#each activeSignals as sig}
                    <div class="dna-row">
                        <span class="dna-label">{sig.label}</span>
                        <div class="dna-bar-bg">
                            <div
                                class="dna-bar-fill"
                                style="width:{sig.value *
                                    100}%; background:{getBarColor(
                                    sig.value,
                                )}; box-shadow: 0 0 6px {getBarColor(
                                    sig.value,
                                )};"
                            ></div>
                        </div>
                        <span
                            class="dna-val"
                            style="color:{getBarColor(sig.value)}"
                            >{Math.round(sig.value * 100)}</span
                        >
                    </div>
                {/each}
            </div>
        </div>

        <!-- Top threats if any -->
        {#if topThreats.length > 0}
            <div class="threat-reasons">
                <div class="section-header">
                    <span class="section-title">Why Blocked</span>
                </div>
                {#each topThreats.slice(0, 3) as t}
                    <div class="reason-pill">
                        <span
                            class="reason-dot"
                            style="background:#ef4444;box-shadow:0 0 6px #ef4444"
                        ></span>
                        <span
                            >{t.label} · {Math.round(t.value * 100)}% confidence</span
                        >
                    </div>
                {/each}
            </div>
        {/if}
    {/if}

    <!-- test buttons (development only) -->
    <div class="test-btns">
        <button class="test-btn safe-btn" on:click={simulateSafe}
            >Simulate Safe</button
        >
        <button class="test-btn threat-btn" on:click={simulateThreat}
            >Simulate Threat</button
        >
    </div>
</div>

<style>
    .shield-wrap {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .url-pill {
        display: flex;
        align-items: center;
        gap: 6px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 7px 12px;
    }
    .url-icon {
        font-size: 11px;
    }
    .url-text {
        font-family: var(--font-mono);
        font-size: 10px;
        color: var(--text-secondary);
        flex: 1;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .status-block {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 18px;
        border-radius: 14px;
        border: 1px solid var(--border);
        background: var(--bg-card);
        transition: all 0.3s ease;
    }
    .status-block.safe {
        border-color: rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.05);
    }
    .status-block.threat {
        border-color: rgba(239, 68, 68, 0.3);
        background: rgba(239, 68, 68, 0.05);
        animation: threatPulse 2s ease infinite;
    }

    @keyframes threatPulse {
        0%,
        100% {
            box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
        }
        50% {
            box-shadow: 0 0 16px 2px rgba(239, 68, 68, 0.15);
        }
    }

    .status-icon-circle {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .status-icon-circle.safe {
        background: rgba(16, 185, 129, 0.1);
    }
    .status-icon-circle.threat {
        background: rgba(239, 68, 68, 0.1);
    }

    .status-label {
        font-size: 15px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .status-sub {
        font-size: 10px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }

    /* Scanning animation */
    .scan-ring {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        border: 2px solid transparent;
        border-top-color: var(--accent);
        border-right-color: var(--accent);
        animation: spin 0.8s linear infinite;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .scan-inner {
        width: 44px;
        height: 44px;
        border-radius: 50%;
        background: rgba(59, 130, 246, 0.1);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
    }
    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }

    /* Risk row */
    .risk-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 8px;
    }
    .risk-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 8px 4px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
    }
    .risk-num {
        font-size: 16px;
        font-weight: 700;
        font-family: var(--font-mono);
        color: var(--accent);
    }
    .risk-num.danger {
        color: var(--accent-red);
    }
    .risk-num.ok {
        color: var(--accent-green);
    }
    .risk-label {
        font-size: 8px;
        color: var(--text-muted);
        text-align: center;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    /* DNA */
    .dna-section {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .section-title {
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }
    .section-badge {
        font-size: 9px;
        padding: 2px 7px;
        background: rgba(59, 130, 246, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.25);
        border-radius: 100px;
        color: var(--accent);
        font-family: var(--font-mono);
        letter-spacing: 0.04em;
    }
    .section-sub {
        font-size: 9px;
        color: var(--text-muted);
        margin-top: -6px;
        font-family: var(--font-mono);
    }

    .dna-bars {
        display: flex;
        flex-direction: column;
        gap: 5px;
    }
    .dna-row {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .dna-label {
        font-size: 9px;
        color: var(--text-muted);
        width: 78px;
        flex-shrink: 0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        font-family: var(--font-mono);
    }
    .dna-bar-bg {
        flex: 1;
        height: 5px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 100px;
        overflow: hidden;
    }
    .dna-bar-fill {
        height: 100%;
        border-radius: 100px;
        transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .dna-val {
        font-size: 9px;
        width: 18px;
        text-align: right;
        font-family: var(--font-mono);
    }

    /* Threat reasons */
    .threat-reasons {
        background: rgba(239, 68, 68, 0.06);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 12px;
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .reason-pill {
        display: flex;
        align-items: center;
        gap: 7px;
        font-size: 10px;
        color: var(--text-secondary);
        font-family: var(--font-mono);
    }
    .reason-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    /* Test buttons */
    .test-btns {
        display: flex;
        gap: 8px;
        margin-top: 4px;
    }
    .test-btn {
        flex: 1;
        padding: 8px;
        border-radius: 8px;
        border: 1px solid;
        background: transparent;
        font-family: var(--font-main);
        font-size: 10px;
        font-weight: 600;
        cursor: pointer;
        letter-spacing: 0.04em;
        transition: all 0.2s ease;
    }
    .safe-btn {
        border-color: var(--accent-green);
        color: var(--accent-green);
    }
    .safe-btn:hover {
        background: rgba(16, 185, 129, 0.1);
    }
    .threat-btn {
        border-color: var(--accent-red);
        color: var(--accent-red);
    }
    .threat-btn:hover {
        background: rgba(239, 68, 68, 0.1);
    }
</style>
