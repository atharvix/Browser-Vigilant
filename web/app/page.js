"use client";
import { useState, useEffect } from "react";
import styles from "./page.module.css";

/* ─── static data ─────────────────────────── */
const onboardingFeatures = [
  { dot: "#34D399", icon: "🔒", title: "Your data stays here", desc: "I don't read your emails. Your personal data never leaves your device." },
  { dot: "#F59E0B", icon: "🌙", title: "A sleeping watchdog", desc: "I only wake up when things look sketchy. Otherwise I'm invisible." },
  { dot: "#818CF8", icon: "🎓", title: "No panic alerts", desc: "Clear, educational context instead of scary red screens." },
];

const protections = [
  { icon: "🛡", color: "#6366F1", title: "Phishing Detection", desc: "Identify fake login pages instantly and warn you before you enter data." },
  { icon: "⛏", color: "#F59E0B", title: "Crypto-Miner Blocking", desc: "Stop websites using your CPU to mine crypto in the background." },
  { icon: "A", color: "#EC4899", title: "Typosquatting Alerts", desc: "Warn on URLs like g00gle.com — one letter off from a real site." },
  { icon: "🤖", color: "#14B8A6", title: "AI + ML Engine", desc: "48-feature Rust WASM + ensemble RF model running fully on-device." },
];

const navItems = [
  { id: "overview", icon: "▦", label: "Overview" },
  { id: "vault", icon: "⛁", label: "Threat Vault" },
  { id: "protections", icon: "🛡", label: "Protections" },
  { id: "allowlist", icon: "☰", label: "Allowlist" },
  { id: "about", icon: "ⓘ", label: "About" },
];

/* ─── helpers ─────────────────────────────── */
function shortHash(h) { return h ? `${h.slice(0, 8)}…${h.slice(-6)}` : "—"; }
function fmtDate(d) { try { return new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }); } catch { return "—"; } }
function confColor(c) { return c >= 0.8 ? "#ef4444" : c >= 0.5 ? "#f59e0b" : "#34d399"; }

/* ─── component ───────────────────────────── */
export default function Home() {
  const [onboarding, setOnboarding] = useState(true);
  const [step, setStep] = useState(0);
  const [nav, setNav] = useState("overview");
  const [vaultData, setVaultData] = useState(null);
  const [vaultLoading, setVaultLoading] = useState(false);

  /* fetch vault stats when navigating to the vault tab */
  useEffect(() => {
    if (nav !== "vault") return;
    setVaultLoading(true);
    fetch("/api/vault/stats")
      .then(r => r.json())
      .then(d => setVaultData(d))
      .catch(() => setVaultData({ error: true }))
      .finally(() => setVaultLoading(false));
  }, [nav]);

  return (
    <>
      {/* ─── Onboarding overlay ─── */}
      {onboarding && (
        <div className={styles.onboardingOverlay}>
          <div className={styles.onboardingCard}>
            {step === 0 ? (
              <div className={styles.onboardingStep}>
                <div className={styles.onboardingIcon}>
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                </div>
                <h1 className={styles.onboardingTitle}>Hi, I&apos;m Browser Vigilant.</h1>
                <p className={styles.onboardingSubtitle}>A different kind of security. Less panic, more peace of mind.</p>
                <div className={styles.featureList}>
                  {onboardingFeatures.map((f, i) => (
                    <div key={i} className={styles.featureRow}>
                      <span className={styles.featureDot} style={{ background: f.dot }} />
                      <div className={styles.featureIconCircle}><span style={{ fontSize: 18 }}>{f.icon}</span></div>
                      <div>
                        <div className={styles.featureTitle}>{f.title}</div>
                        <div className={styles.featureDesc}>{f.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <button className={styles.primaryBtn} onClick={() => setStep(1)}>Learn how it works →</button>
                <p className={styles.onboardingNote}>By clicking start, you agree to Browser Vigilant&apos;s <a href="/privacy" style={{ textDecoration: "underline", color: "#FF7B6B" }}>Privacy Policy</a>.</p>
              </div>
            ) : (
              <div className={styles.onboardingStep}>
                <div className={styles.onboardingIconGreen}>
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
                <h1 className={styles.onboardingTitle}>100% On-Device</h1>
                <p className={styles.onboardingSubtitle}>Our AI runs in your browser via Rust + WebAssembly. No cloud, no servers, no data sent.</p>
                <div className={styles.techPills}>
                  {["Rust WASM", "SHA-256 Ledger", "48 Features", "RF + GBM Ensemble", "Zero API Calls"].map(t => (
                    <span key={t} className={styles.techPill}>{t}</span>
                  ))}
                </div>
                <button className={styles.primaryBtn} onClick={() => setOnboarding(false)}>Start Browsing →</button>
                <button className={styles.ghostBtnLight} onClick={() => setStep(0)}>← Back</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── App Shell ─── */}
      <div className={styles.shell}>
        {/* Sidebar */}
        <aside className={styles.sidebar}>
          <div className={styles.sidebarBrand}>
            <div className={styles.sidebarLogo}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34D399" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <div className={styles.brandName}>Browser Vigilant</div>
              <div className={styles.brandSub}>Friendly Security</div>
            </div>
          </div>

          <nav className={styles.sidebarNav}>
            {navItems.map(item => (
              <button
                key={item.id}
                className={`${styles.navItem} ${nav === item.id ? styles.navItemActive : ""}`}
                onClick={() => setNav(item.id)}
              >
                <span className={styles.navIcon}>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            ))}
          </nav>

          <div className={styles.sidebarStatus}>
            <span className={styles.statusDot} />
            <span className={styles.statusText}>Everything looks good.</span>
          </div>
        </aside>

        {/* Main */}
        <main className={styles.main}>

          {/* ── Overview ── */}
          {nav === "overview" && (
            <>
              <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>Your Safety Overview</h1>
                <p className={styles.pageSubtitle}>Here&apos;s how Browser Vigilant has been helping you.</p>
              </div>

              <div className={styles.statsGrid}>
                <div className={`${styles.statCard} ${styles.statCardLarge}`}>
                  <div className={styles.statCardInner}>
                    <div>
                      <div className={styles.statLabel}>Scams avoided</div>
                      <div className={styles.statNumber}>14 <span className={styles.statDelta}>+2 this week</span></div>
                      <p className={styles.statDesc}>That&apos;s 14 times we stepped in to gently pause a connection before it could do any harm. Great job staying safe!</p>
                    </div>
                    <div className={styles.statIllustration}>
                      <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="rgba(255,123,107,0.12)" strokeWidth="1.5">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                    </div>
                  </div>
                </div>
                <div className={styles.statCardStack}>
                  <div className={`${styles.statCard} ${styles.statCardSm}`}>
                    <div className={styles.statSmIcon} style={{ background: "rgba(255,123,107,0.1)" }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF7B6B" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
                      </svg>
                    </div>
                    <div className={styles.statSmNumber}>2.4s</div>
                    <div className={styles.statSmLabel}>AVG. LOAD TIME SAVED</div>
                  </div>
                  <div className={`${styles.statCard} ${styles.statCardSm}`}>
                    <div className={styles.statSmIcon} style={{ background: "rgba(52,211,153,0.1)" }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#34D399" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </svg>
                    </div>
                    <div className={styles.statSmNumber}>128</div>
                    <div className={styles.statSmLabel}>TRACKERS BLOCKED</div>
                  </div>
                </div>
              </div>

              {/* CTA */}
              <div className={styles.ctaCard}>
                <div>
                  <h2 className={styles.ctaTitle}>Get Browser Vigilant</h2>
                  <p className={styles.ctaDesc}>Load as an unpacked Chrome extension and start protecting your browsing immediately.</p>
                  <div className={styles.ctaBtns}>
                    <a href="https://github.com/Prekshas27/Browser-Vigilant" target="_blank" rel="noreferrer" className={styles.primaryBtn}>
                      ⭐ View on GitHub
                    </a>
                    <button className={styles.ghostBtn} onClick={() => setNav("vault")}>
                      ⛁ View Threat DB
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* ── Threat Vault ── */}
          {nav === "vault" && (
            <>
              <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>Decentralized Threat Vault</h1>
                <p className={styles.pageSubtitle}>SHA-256 hashed domain blocklist — synced from all extension clients. No raw URLs stored.</p>
              </div>

              {vaultLoading && (
                <div className={styles.loadingRow}>
                  <div className={styles.spinnerRing} /> Loading vault data…
                </div>
              )}

              {!vaultLoading && vaultData && !vaultData.error && (
                <>
                  {/* Vault stat cards */}
                  <div className={styles.vaultStats}>
                    <div className={styles.vaultStatCard}>
                      <div className={styles.vaultStatNum}>{vaultData.totalThreats ?? 0}</div>
                      <div className={styles.vaultStatLabel}>HASHED THREATS</div>
                    </div>
                    <div className={styles.vaultStatCard}>
                      <div className={styles.vaultStatNum}>{vaultData.totalSyncs ?? 0}</div>
                      <div className={styles.vaultStatLabel}>TOTAL SYNCS</div>
                    </div>
                    <div className={styles.vaultStatCard}>
                      <div className={styles.vaultStatNum}>{vaultData.sourceBreakdown?.length ?? 0}</div>
                      <div className={styles.vaultStatLabel}>SOURCES</div>
                    </div>
                    <div className={`${styles.vaultStatCard} ${styles.vaultStatCardGreen}`}>
                      <div className={styles.vaultStatNum} style={{ color: "#34D399" }}>100%</div>
                      <div className={styles.vaultStatLabel}>PRIVACY PRESERVED</div>
                    </div>
                  </div>

                  {/* Source breakdown */}
                  {vaultData.sourceBreakdown?.length > 0 && (
                    <div className={styles.section}>
                      <h2 className={styles.sectionTitle}>Submission Sources</h2>
                      <div className={styles.sourceGrid}>
                        {vaultData.sourceBreakdown.map(s => (
                          <div key={s.source} className={styles.sourceCard}>
                            <div className={styles.sourceCount}>{s.count}</div>
                            <div className={styles.sourceLabel}>{s.source}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recent entries table */}
                  <div className={styles.section}>
                    <div className={styles.sectionHeader}>
                      <h2 className={styles.sectionTitle}>Recent Threat Hashes</h2>
                      <span className={styles.privacyBadge}>🔒 SHA-256 · No raw URLs</span>
                    </div>
                    <div className={styles.tableWrap}>
                      <table className={styles.table}>
                        <thead>
                          <tr>
                            <th>HASH (truncated)</th>
                            <th>SOURCE</th>
                            <th>CONFIDENCE</th>
                            <th>ADDED</th>
                          </tr>
                        </thead>
                        <tbody>
                          {vaultData.recentThreats?.length === 0 && (
                            <tr><td colSpan={4} className={styles.emptyRow}>Vault is empty — no threats submitted yet.</td></tr>
                          )}
                          {vaultData.recentThreats?.map((t, i) => (
                            <tr key={i}>
                              <td><code className={styles.hashCode}>{shortHash(t.hash)}</code></td>
                              <td><span className={styles.sourcePill}>{t.source}</span></td>
                              <td>
                                <span style={{ color: confColor(t.confidence), fontWeight: 700 }}>
                                  {(t.confidence * 100).toFixed(0)}%
                                </span>
                              </td>
                              <td className={styles.dateCell}>{fmtDate(t.createdAt)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className={styles.vaultFootnote}>
                      SHA-256(hostname) — one-way hash. Original URLs are never stored or transmitted.
                      The extension submits hashes anonymously after blocking a domain.
                    </p>
                  </div>
                </>
              )}

              {!vaultLoading && vaultData?.error && (
                <div className={styles.errorCard}>
                  ⚠ Could not connect to the Vault API. Make sure the Next.js server and database are running.
                </div>
              )}
            </>
          )}

          {/* ── Protections ── */}
          {nav === "protections" && (
            <>
              <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>Active Protections</h1>
                <p className={styles.pageSubtitle}>Configure what Browser Vigilant checks for.</p>
              </div>
              <div className={styles.protectionsList}>
                {protections.map(p => (
                  <div key={p.title} className={styles.protectionRow}>
                    <div className={styles.protectionIcon} style={{ background: `${p.color}18` }}>
                      <span style={{ color: p.color, fontSize: 14, fontWeight: 700 }}>{p.icon}</span>
                    </div>
                    <div className={styles.protectionInfo}>
                      <div className={styles.protectionTitle}>{p.title}</div>
                      <div className={styles.protectionDesc}>{p.desc}</div>
                    </div>
                    <div className={`${styles.toggle} ${styles.toggleOn}`}>
                      <div className={styles.toggleKnob} />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {/* ── Allowlist ── */}
          {nav === "allowlist" && (
            <>
              <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>Trusted Domains</h1>
                <p className={styles.pageSubtitle}>Sites you&apos;ve marked as safe, even if they look unusual.</p>
              </div>
              <div className={styles.sectionHeader}>
                <div />
                <button className={styles.addBtn}>+ Add Domain</button>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>DOMAIN NAME</th><th>DATE ADDED</th><th>ACTIONS</th></tr>
                  </thead>
                  <tbody>
                    <tr><td colSpan={3} className={styles.emptyRow}>No trusted domains yet.</td></tr>
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* ── About ── */}
          {nav === "about" && (
            <>
              <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>About Browser Vigilant</h1>
                <p className={styles.pageSubtitle}>An open-source, privacy-first security extension.</p>
              </div>
              <div className={styles.aboutGrid}>
                {[
                  ["Version", "2.0.0"],
                  ["ML Model", "RF×300 + GBM×200 Ensemble"],
                  ["Feature Extraction", "48 features via Rust WASM"],
                  ["Ledger", "SHA-256 Local Blockchain"],
                  ["Community Vault", "Decentralized threat hash DB"],
                  ["Privacy", "100% On-Device — Zero Data Shared"],
                ].map(([k, v]) => (
                  <div key={k} className={styles.aboutRow}>
                    <span className={styles.aboutKey}>{k}</span>
                    <span className={styles.aboutVal} style={k === "Privacy" ? { color: "#34D399", fontWeight: 700 } : {}}>{v}</span>
                  </div>
                ))}
              </div>
              <div className={styles.ctaCard} style={{ marginTop: 24 }}>
                <h2 className={styles.ctaTitle}>Open Source</h2>
                <p className={styles.ctaDesc}>Browser Vigilant is fully open source. Star it on GitHub, contribute, or report issues.</p>
                <a href="https://github.com/Prekshas27/Browser-Vigilant" target="_blank" rel="noreferrer" className={styles.primaryBtn}>
                  ⭐ View on GitHub
                </a>
              </div>
            </>
          )}

        </main>
      </div>
    </>
  );
}
