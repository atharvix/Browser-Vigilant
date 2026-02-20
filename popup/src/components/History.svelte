<script>
    // Simulated scan history — in production stored in chrome.storage.local / IndexedDB
    const history = [
        {
            url: "https://www.google.com",
            status: "safe",
            time: "10:22 AM",
            ms: 1.8,
        },
        {
            url: "http://paypal-secure-login.xyz/verify",
            status: "blocked",
            time: "10:19 AM",
            ms: 2.1,
        },
        {
            url: "https://github.com",
            status: "safe",
            time: "10:15 AM",
            ms: 1.2,
        },
        {
            url: "http://amaz0n.account-verify.top/login",
            status: "blocked",
            time: "09:58 AM",
            ms: 2.4,
        },
        {
            url: "https://stackoverflow.com",
            status: "safe",
            time: "09:44 AM",
            ms: 1.6,
        },
        {
            url: "https://drive.google.com",
            status: "safe",
            time: "09:31 AM",
            ms: 1.3,
        },
        {
            url: "http://xn--pple-43d.com/signin",
            status: "blocked",
            time: "09:20 AM",
            ms: 3.0,
        },
    ];

    function formatUrl(url) {
        return url.length > 36 ? url.slice(0, 33) + "..." : url;
    }
</script>

<div class="history-wrap">
    <div class="summary-row">
        <div class="sum-card safe">
            <span class="sum-num"
                >{history.filter((h) => h.status === "safe").length}</span
            >
            <span class="sum-label">Safe Sites</span>
        </div>
        <div class="sum-card blocked">
            <span class="sum-num"
                >{history.filter((h) => h.status === "blocked").length}</span
            >
            <span class="sum-label">Blocked</span>
        </div>
        <div class="sum-card">
            <span class="sum-num"
                >{(
                    history.reduce((a, h) => a + h.ms, 0) / history.length
                ).toFixed(1)}ms</span
            >
            <span class="sum-label">Avg Scan</span>
        </div>
    </div>

    <div class="list-header">
        <span class="section-title">Recent Scans</span>
        <span class="section-badge">Today</span>
    </div>

    <div class="scan-list">
        {#each history as item}
            <div class="scan-item">
                <div class="scan-status-dot {item.status}"></div>
                <div class="scan-info">
                    <span class="scan-url">{formatUrl(item.url)}</span>
                    <span class="scan-meta">{item.time} · {item.ms}ms scan</span
                    >
                </div>
                <div class="scan-badge {item.status}">
                    {#if item.status === "safe"}✅ Safe{:else}🚫 Blocked{/if}
                </div>
            </div>
        {/each}
    </div>
</div>

<style>
    .history-wrap {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .summary-row {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 8px;
    }
    .sum-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px 8px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
    }
    .sum-card.safe {
        border-color: rgba(16, 185, 129, 0.25);
        background: rgba(16, 185, 129, 0.05);
    }
    .sum-card.blocked {
        border-color: rgba(239, 68, 68, 0.25);
        background: rgba(239, 68, 68, 0.05);
    }
    .sum-num {
        font-size: 20px;
        font-weight: 700;
        font-family: var(--font-mono);
        color: var(--text-primary);
    }
    .sum-label {
        font-size: 9px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .list-header {
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
        font-family: var(--font-mono);
    }

    .scan-list {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .scan-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        transition: border-color 0.2s;
    }
    .scan-item:hover {
        border-color: var(--border-glow);
    }
    .scan-status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        flex-shrink: 0;
    }
    .scan-status-dot.safe {
        background: #10b981;
        box-shadow: 0 0 5px #10b981;
    }
    .scan-status-dot.blocked {
        background: #ef4444;
        box-shadow: 0 0 5px #ef4444;
    }

    .scan-info {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .scan-url {
        font-size: 10px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .scan-meta {
        font-size: 9px;
        color: var(--text-muted);
    }

    .scan-badge {
        font-size: 9px;
        font-weight: 600;
        white-space: nowrap;
        padding: 3px 7px;
        border-radius: 100px;
        flex-shrink: 0;
    }
    .scan-badge.safe {
        background: rgba(16, 185, 129, 0.1);
        color: var(--accent-green);
        border: 1px solid rgba(16, 185, 129, 0.25);
    }
    .scan-badge.blocked {
        background: rgba(239, 68, 68, 0.1);
        color: var(--accent-red);
        border: 1px solid rgba(239, 68, 68, 0.25);
    }
</style>
