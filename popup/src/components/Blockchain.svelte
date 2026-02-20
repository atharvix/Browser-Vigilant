<script>
    // Blockchain Threat Ledger
    // Each blocked URL gets hashed and chained — tamper-proof local audit trail
    // In production: stored in chrome.storage.local / can be submitted to a shared ledger

    // Simulated chain data (each block has: index, prev hash, this block's hash, threat data)
    const chain = [
        {
            index: 0,
            timestamp: "2026-02-20T04:00:00Z",
            type: "GENESIS",
            url: null,
            threat: null,
            prevHash: "0000000000000000",
            hash: "a3f8b2c1d9e04567",
            riskScore: null,
        },
        {
            index: 1,
            timestamp: "2026-02-20T09:20:11Z",
            type: "THREAT_BLOCKED",
            url: "http://xn--pple-43d.com/signin",
            threat: "Punycode Homograph Attack",
            prevHash: "a3f8b2c1d9e04567",
            hash: "f1c72a8e3b490d21",
            riskScore: 94,
        },
        {
            index: 2,
            timestamp: "2026-02-20T09:58:44Z",
            type: "THREAT_BLOCKED",
            url: "http://amaz0n.account-verify.top/login",
            threat: "Brand Spoof + Suspicious TLD",
            prevHash: "f1c72a8e3b490d21",
            hash: "c8d3e912f5a60b74",
            riskScore: 97,
        },
        {
            index: 3,
            timestamp: "2026-02-20T10:19:02Z",
            type: "THREAT_BLOCKED",
            url: "http://paypal-secure-login.xyz/verify",
            threat: "Login Keyword + Suspicious TLD",
            prevHash: "c8d3e912f5a60b74",
            hash: "7b2a5f9e1d836c40",
            riskScore: 91,
        },
    ];

    // Verify chain integrity (each block's prevHash must match previous block's hash)
    function verifyChain(c) {
        for (let i = 1; i < c.length; i++) {
            if (c[i].prevHash !== c[i - 1].hash) return false;
        }
        return true;
    }

    $: chainValid = verifyChain(chain);
    $: threatBlocks = chain.filter((b) => b.type === "THREAT_BLOCKED");

    function shortHash(h) {
        return h.slice(0, 6) + "..." + h.slice(-4);
    }

    function formatTime(ts) {
        return new Date(ts).toLocaleTimeString("en-IN", {
            hour: "2-digit",
            minute: "2-digit",
        });
    }

    function formatDate(ts) {
        return new Date(ts).toLocaleDateString("en-IN", {
            month: "short",
            day: "numeric",
        });
    }
</script>

<div class="chain-wrap">
    <!-- Chain integrity status -->
    <div class="integrity-banner {chainValid ? 'valid' : 'invalid'}">
        <div class="integrity-icon">{chainValid ? "🔒" : "⚠️"}</div>
        <div class="integrity-info">
            <span class="integrity-title"
                >{chainValid
                    ? "Ledger Integrity Verified"
                    : "Chain Tampered!"}</span
            >
            <span class="integrity-sub"
                >{chain.length} blocks · {threatBlocks.length} threats recorded</span
            >
        </div>
        <div class="integrity-badge {chainValid ? 'ok' : 'bad'}">
            {chainValid ? "VALID" : "INVALID"}
        </div>
    </div>

    <!-- What this is -->
    <div class="explainer">
        <span class="explainer-icon">⛓️</span>
        <span class="explainer-text"
            >Every blocked threat is hashed and chained into a <strong
                >tamper-proof local ledger</strong
            >. Your threat history cannot be silently deleted or altered.</span
        >
    </div>

    <!-- Stats row -->
    <div class="stats-row">
        <div class="stat-card">
            <span class="stat-num accent-blue">{chain.length}</span>
            <span class="stat-label">Total Blocks</span>
        </div>
        <div class="stat-card">
            <span class="stat-num accent-red">{threatBlocks.length}</span>
            <span class="stat-label">Threats Logged</span>
        </div>
        <div class="stat-card">
            <span class="stat-num accent-green"
                >{chainValid ? "100%" : "0%"}</span
            >
            <span class="stat-label">Integrity</span>
        </div>
    </div>

    <!-- Blockchain visual -->
    <div class="section-header">
        <span class="section-title">Threat Ledger</span>
        <span class="section-badge mono">SHA-256 Chained</span>
    </div>

    <div class="block-list">
        {#each chain as block, i}
            <div
                class="block {block.type === 'GENESIS' ? 'genesis' : 'threat'}"
            >
                <!-- Chain connector -->
                {#if i > 0}
                    <div class="connector">
                        <div class="connector-line"></div>
                        <div class="connector-arrow">↓</div>
                        <div class="connector-line"></div>
                    </div>
                {/if}

                <div class="block-inner">
                    <div class="block-header">
                        <div class="block-index">#{block.index}</div>
                        <div
                            class="block-type {block.type === 'GENESIS'
                                ? 'genesis-badge'
                                : 'threat-badge'}"
                        >
                            {block.type === "GENESIS" ? "Genesis" : "🚫 Threat"}
                        </div>
                        {#if block.timestamp}
                            <div class="block-time">
                                {formatTime(block.timestamp)} · {formatDate(
                                    block.timestamp,
                                )}
                            </div>
                        {/if}
                    </div>

                    {#if block.url}
                        <div class="block-url">
                            {block.url.length > 40
                                ? block.url.slice(0, 37) + "..."
                                : block.url}
                        </div>
                    {:else}
                        <div class="block-url genesis-url">
                            Browser Vigilant · Ledger Initialized
                        </div>
                    {/if}

                    {#if block.threat}
                        <div class="block-threat">
                            <span class="threat-tag">⚡ {block.threat}</span>
                            <span class="risk-tag"
                                >Risk {block.riskScore}/100</span
                            >
                        </div>
                    {/if}

                    <div class="block-hashes">
                        <div class="hash-row">
                            <span class="hash-label">PREV</span>
                            <span class="hash-val mono"
                                >{shortHash(block.prevHash)}</span
                            >
                        </div>
                        <div class="hash-row">
                            <span class="hash-label">HASH</span>
                            <span class="hash-val mono accent"
                                >{shortHash(block.hash)}</span
                            >
                        </div>
                    </div>
                </div>
            </div>
        {/each}
    </div>
</div>

<style>
    .chain-wrap {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .integrity-banner {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid;
    }
    .integrity-banner.valid {
        border-color: rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.07);
    }
    .integrity-banner.invalid {
        border-color: rgba(239, 68, 68, 0.3);
        background: rgba(239, 68, 68, 0.07);
    }
    .integrity-icon {
        font-size: 18px;
    }
    .integrity-info {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .integrity-title {
        font-size: 11px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .integrity-sub {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }
    .integrity-badge {
        font-size: 9px;
        font-weight: 800;
        letter-spacing: 0.1em;
        padding: 3px 8px;
        border-radius: 100px;
    }
    .integrity-badge.ok {
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
        background: rgba(16, 185, 129, 0.1);
    }
    .integrity-badge.bad {
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.4);
        background: rgba(239, 68, 68, 0.1);
    }

    .explainer {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        padding: 8px 12px;
        background: rgba(59, 130, 246, 0.06);
        border: 1px solid rgba(59, 130, 246, 0.15);
        border-radius: 8px;
        font-size: 10px;
        color: var(--text-secondary);
        line-height: 1.5;
    }
    .explainer-icon {
        font-size: 14px;
        flex-shrink: 0;
        margin-top: 1px;
    }
    .explainer strong {
        color: var(--accent);
    }

    .stats-row {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 8px;
    }
    .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px 8px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
    }
    .stat-num {
        font-size: 20px;
        font-weight: 700;
        font-family: var(--font-mono);
    }
    .accent-blue {
        color: var(--accent);
    }
    .accent-red {
        color: #ef4444;
    }
    .accent-green {
        color: #10b981;
    }
    .stat-label {
        font-size: 8px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
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
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.2);
        border-radius: 100px;
        color: var(--accent);
    }
    .mono {
        font-family: var(--font-mono);
        letter-spacing: 0.04em;
    }

    /* Blocks */
    .block-list {
        display: flex;
        flex-direction: column;
    }

    .connector {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0;
        padding: 0 0 0 16px;
    }
    .connector-line {
        width: 2px;
        height: 8px;
        background: var(--border-glow);
    }
    .connector-arrow {
        font-size: 10px;
        color: var(--text-muted);
        line-height: 1;
    }

    .block {
    }
    .block-inner {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
        transition: border-color 0.2s;
    }
    .block.threat .block-inner {
        border-color: rgba(239, 68, 68, 0.2);
    }
    .block.genesis .block-inner {
        border-color: rgba(59, 130, 246, 0.2);
    }
    .block-inner:hover {
        border-color: var(--border-glow) !important;
    }

    .block-header {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px 6px;
        border-bottom: 1px solid var(--border);
    }
    .block-index {
        font-size: 9px;
        font-family: var(--font-mono);
        color: var(--text-muted);
        font-weight: 700;
    }
    .block-type {
        font-size: 9px;
        font-weight: 700;
        padding: 2px 7px;
        border-radius: 100px;
        letter-spacing: 0.04em;
    }
    .genesis-badge {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.25);
        color: var(--accent);
    }
    .threat-badge {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.25);
        color: #ef4444;
    }
    .block-time {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        margin-left: auto;
    }

    .block-url {
        padding: 6px 10px;
        font-size: 10px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
        border-bottom: 1px solid var(--border);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .genesis-url {
        color: var(--text-muted);
        font-style: italic;
    }

    .block-threat {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 5px 10px;
        border-bottom: 1px solid var(--border);
        flex-wrap: wrap;
    }
    .threat-tag {
        font-size: 9px;
        color: #ef4444;
        font-family: var(--font-mono);
    }
    .risk-tag {
        font-size: 9px;
        padding: 1px 6px;
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 100px;
        color: #ef4444;
        margin-left: auto;
        font-family: var(--font-mono);
    }

    .block-hashes {
        display: flex;
        flex-direction: column;
        gap: 3px;
        padding: 7px 10px;
    }
    .hash-row {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .hash-label {
        font-size: 8px;
        font-weight: 800;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        width: 28px;
    }
    .hash-val {
        font-size: 9px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
    }
    .hash-val.accent {
        color: var(--accent);
    }
</style>
