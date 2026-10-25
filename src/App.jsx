
import React, { useCallback, useEffect, useMemo, useState } from "react";

const API = "http://127.0.0.1:8000";

const DEMO_CSV = `timestamp,username,source_ip,event_type,status,event_source
2026-10-24T18:59:00,analyst01,203.0.113.25,login,failed,identity
2026-10-24T19:00:00,analyst01,203.0.113.25,login,failed,identity
2026-10-24T19:01:00,analyst01,203.0.113.25,login,failed,identity
2026-10-24T19:02:00,analyst01,203.0.113.25,login,failed,identity
2026-10-24T19:03:00,analyst01,203.0.113.25,login,failed,identity
2026-10-24T19:04:00,analyst01,203.0.113.25,login,success,identity
2026-10-24T19:06:00,analyst01,203.0.113.25,permission_change,success,identity
2026-10-24T19:10:00,cloudadmin,198.51.100.14,login,success,identity
2026-10-24T19:22:00,service-account,192.0.2.40,storage_read,success,storage
2026-10-24T20:20:00,analyst01,203.0.113.25,delete_trail,success,audit
2026-10-24T22:16:00,unknown-user,198.51.100.77,login,success,identity
2026-10-24T22:18:00,cloudadmin,198.51.100.14,policy_update,success,identity`;

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}

function shortHash(hash = "") {
  if (!hash) return "Not available";
  return `${hash.slice(0, 12)}…${hash.slice(-8)}`;
}

function levelClass(level = "Low") {
  const normalized = String(level).toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "uncorrelated") return "muted";
  return "low";
}

function Logo() {
  return (
    <svg
      viewBox="0 0 64 64"
      className="logo-mark"
      role="img"
      aria-label="TraceLens logo"
    >
      <circle
        cx="27"
        cy="27"
        r="20"
        fill="none"
        stroke="#44e0d0"
        strokeWidth="5"
      />
      <path
        d="M42 42 L55 55"
        fill="none"
        stroke="#44e0d0"
        strokeWidth="7"
        strokeLinecap="round"
      />
      <path
        d="M17 27 L24 34 L38 19"
        fill="none"
        stroke="#44e0d0"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Icon({ name, size = 18 }) {
  const paths = {
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    upload: (
      <>
        <path d="M12 16V4" />
        <path d="m7 9 5-5 5 5" />
        <path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" />
      </>
    ),
    shield: (
      <>
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
        <path d="m9 12 2 2 4-4" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    ),
    search: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-4-4" />
      </>
    ),
    download: (
      <>
        <path d="M12 3v12" />
        <path d="m7 10 5 5 5-5" />
        <path d="M5 21h14" />
      </>
    ),
    refresh: (
      <>
        <path d="M20 7v5h-5" />
        <path d="M4 17v-5h5" />
        <path d="M5.6 9A7 7 0 0 1 18 6l2 6" />
        <path d="M18.4 15A7 7 0 0 1 6 18l-2-6" />
      </>
    ),
    alert: (
      <>
        <path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z" />
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
      </>
    ),
    file: (
      <>
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
        <path d="M14 2v6h6" />
        <path d="M8 13h8M8 17h8" />
      </>
    ),
    chevron: <path d="m9 18 6-6-6-6" />,
    check: <path d="m5 12 4 4L19 6" />,
  };

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name] || paths.file}
    </svg>
  );
}

function Badge({ level, children }) {
  return (
    <span className={`badge ${levelClass(level)}`}>
      {children || level || "Low"}
    </span>
  );
}

/*
 * Breaks down the correlation score using the same rules as main.py.
 * It explains the score; it does not independently determine whether
 * an event is malicious.
 */
function getCorrelationBreakdown(story) {
  const events = Array.isArray(story?.events) ? story.events : [];
  const eventCount = events.length;

  const base = Math.min(
    30,
    15 + 5 * Math.max(0, eventCount - 2)
  );

  const normalized = events.map((event) => ({
    name: String(
      event.event_type || event.event_name || ""
    ).toLowerCase(),
    status: String(event.status || "").toLowerCase(),
    time: event.timestamp ? new Date(event.timestamp) : null,
  }));

  const isSuccess = (item) =>
    /success|succeeded|allowed|accepted|complete|^ok$/.test(
      item.status
    ) &&
    !/fail|denied|invalid|reject|error/.test(item.status);

  const isLogin = (item) =>
    /login|log_in|signin|sign_in|authentication|auth/.test(
      item.name
    );

  const isPermission = (item) =>
    /permission|policy|privilege|role|access.?key|admin/.test(
      item.name
    );

  const isAuditRisk = (item) =>
    (
      /delete/.test(item.name) &&
      /trail|audit|log/.test(item.name)
    ) ||
    /stop.?logging/.test(item.name) ||
    (
      /disable/.test(item.name) &&
      /logging|audit|trail/.test(item.name)
    );

  const hasSuccessfulLogin = normalized.some(
    (item) => isLogin(item) && isSuccess(item)
  );

  const hasPermissionChange = normalized.some(isPermission);
  const hasAuditRisk = normalized.some(isAuditRisk);

  const timeline = normalized
    .filter(
      (item) =>
        item.time instanceof Date &&
        !Number.isNaN(item.time.getTime())
    )
    .sort((a, b) => a.time - b.time);

  const loginEvent = timeline.find(
    (item) => isLogin(item) && isSuccess(item)
  );

  const permissionEvent = loginEvent
    ? timeline.find(
        (item) =>
          item.time > loginEvent.time && isPermission(item)
      )
    : null;

  const auditEvent = permissionEvent
    ? timeline.find(
        (item) =>
          item.time > permissionEvent.time && isAuditRisk(item)
      )
    : null;

  const sequenceBonus = Boolean(
    loginEvent &&
    permissionEvent &&
    auditEvent &&
    auditEvent.time.getTime() - loginEvent.time.getTime() <=
      2 * 60 * 60 * 1000
  );

  const items = [
    {
      label: "Related-event base",
      points: base,
      description: "Base points for a group of flagged events.",
    },
    {
      label: "Successful login",
      points: hasSuccessfulLogin ? 10 : 0,
      description: "Added if the group contains a successful login.",
    },
    {
      label: "Permission / privilege action",
      points: hasPermissionChange ? 20 : 0,
      description: "Added if the group contains a sensitive access change.",
    },
    {
      label: "Audit / logging risk",
      points: hasAuditRisk ? 25 : 0,
      description: "Added if an audit/logging action may reduce visibility.",
    },
    {
      label: "Ordered sequence bonus",
      points: sequenceBonus ? 15 : 0,
      description:
        "Added when login, permission change, and audit risk occur in order within two hours.",
    },
  ];

  const rawTotal = items.reduce(
    (total, item) => total + item.points,
    0
  );

  return {
    items,
    total: Math.min(100, rawTotal),
    capped: rawTotal > 100,
  };
}

function StatCard({
  label,
  value,
  caption,
  icon,
  tone = "teal",
}) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>
        <Icon name={icon} size={19} />
      </div>
      <div className="stat-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{caption}</small>
      </div>
    </div>
  );
}

export default function App() {
  const [apiStatus, setApiStatus] = useState("checking");
  const [cases, setCases] = useState([]);
  const [activeCase, setActiveCase] = useState(null);
  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [dragging, setDragging] = useState(false);

  const findings = activeCase?.findings || [];
  const events = activeCase?.events || [];
  const storylines = activeCase?.storylines || [];

  const selectedFinding =
    findings.find(
      (item) =>
        String(item.id ?? item.event_id) ===
        String(selectedFindingId)
    ) ||
    findings[0] ||
    null;

  const refreshCases = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/cases`);

      if (!response.ok) {
        throw new Error("Could not load investigation history.");
      }

      const data = await response.json();
      setCases(data.cases || []);
      setApiStatus("connected");
    } catch {
      setApiStatus("offline");
    }
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/health`);

      if (!response.ok) {
        throw new Error("API unavailable");
      }

      setApiStatus("connected");
    } catch {
      setApiStatus("offline");
    }
  }, []);

  useEffect(() => {
    checkHealth();
    refreshCases();
  }, [checkHealth, refreshCases]);

  const loadCase = useCallback(async (caseId) => {
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${API}/api/cases/${caseId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Could not open this investigation."
        );
      }

      setActiveCase(data);
      setSelectedFindingId(
        data.findings?.[0]?.id ??
        data.findings?.[0]?.event_id ??
        null
      );
      setFilter("All");
      setSearch("");
    } catch (err) {
      setError(err.message || "Could not load investigation.");
    }
  }, []);

  const analyzeFile = useCallback(
    async (file) => {
      if (!file) return;

      if (!file.name.toLowerCase().endsWith(".csv")) {
        setError("Please choose a .csv file.");
        return;
      }

      if (file.size > 10 * 1024 * 1024) {
        setError("The maximum upload size is 10 MB.");
        return;
      }

      setBusy(true);
      setError("");
      setNotice("");

      try {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch(`${API}/api/analyze`, {
          method: "POST",
          body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "Analysis failed.");
        }

        setActiveCase(data);
        setSelectedFindingId(
          data.findings?.[0]?.id ??
          data.findings?.[0]?.event_id ??
          null
        );
        setFilter("All");
        setSearch("");

        setNotice(
          `Analysis complete: ${
            data.flagged_count ?? data.findings?.length ?? 0
          } flagged events found.`
        );

        await refreshCases();
      } catch (err) {
        setError(
          `${err.message || "Could not analyze file."} ` +
          "Check that the Python API is running on port 8000."
        );
      } finally {
        setBusy(false);
      }
    },
    [refreshCases]
  );

  const runDemo = useCallback(async () => {
    const file = new File(
      [DEMO_CSV],
      "tracelens-demo-cloud-logs.csv",
      { type: "text/csv" }
    );

    await analyzeFile(file);
  }, [analyzeFile]);

  const filteredFindings = useMemo(
    () =>
      findings.filter((item) => {
        const severity = String(item.severity || "Low");

        const searchText = (
          `${item.username || ""} ` +
          `${item.source_ip || ""} ` +
          `${item.event_type || item.event_name || ""} ` +
          `${item.status || ""} ` +
          `${(item.reasons || []).join(" ")}`
        ).toLowerCase();

        const filterMatches =
          filter === "All" ||
          severity.toLowerCase() === filter.toLowerCase();

        return (
          filterMatches &&
          searchText.includes(search.toLowerCase())
        );
      }),
    [findings, filter, search]
  );

  const highCritical = findings.filter((item) =>
    ["high", "critical"].includes(
      String(item.severity).toLowerCase()
    )
  ).length;

  const groupedFlagged = findings.filter(
    (item) => Number(item.correlation_score || 0) >= 40
  ).length;

  const topCorrelation = storylines.reduce(
    (top, item) =>
      Number(item.correlation_score || 0) >
      Number(top?.correlation_score || 0)
        ? item
        : top,
    null
  );

  const downloadReport = () => {
    if (!activeCase?.case_id && !activeCase?.id) {
      setError("Run an analysis first to download a report.");
      return;
    }

    window.location.href =
      `${API}/api/cases/${activeCase.case_id || activeCase.id}/report`;
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    analyzeFile(event.dataTransfer.files?.[0]);
  };

  return (
    <div className="app-shell">
      <style>{styles}</style>

      <aside className="sidebar">
        <div className="brand">
          <Logo />
          <div>
            <strong>TraceLens</strong>
            <span>Digital Evidence Analyzer</span>
          </div>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <button
          className="side-link active"
          onClick={() =>
            window.scrollTo({ top: 0, behavior: "smooth" })
          }
        >
          <Icon name="grid" /> Overview
        </button>

        <button
          className="side-link"
          onClick={() =>
            document
              .getElementById("upload-section")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          <Icon name="upload" /> New analysis
        </button>

        <button
          className="side-link"
          onClick={() =>
            document
              .getElementById("findings-section")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          <Icon name="alert" /> Findings
          <span className="side-count">{findings.length}</span>
        </button>

        <button
          className="side-link"
          onClick={() =>
            document
              .getElementById("history-section")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          <Icon name="clock" /> Case history
        </button>

        <div className="sidebar-spacer" />

        <div className="sidebar-note">
          <div className="note-icon">
            <Icon name="shield" size={18} />
          </div>
          <strong>Evidence-first workflow</strong>
          <p>
            TraceLens surfaces leads for analyst review. Validate
            findings against source records.
          </p>
        </div>

        <div className="sidebar-footer">
          <span className={`status-dot ${apiStatus}`} />
          API{" "}
          {apiStatus === "connected"
            ? "Connected"
            : apiStatus === "checking"
              ? "Connecting…"
              : "Offline"}
          <span className="version">v1.1</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="mobile-brand">
            <Logo />
            <strong>TraceLens</strong>
          </div>

          <div>
            <span className="eyebrow">
              CLOUD FORENSICS / WORKSPACE
            </span>
            <h1>Investigation overview</h1>
          </div>

          <div className="topbar-actions">
            <span className={`api-pill ${apiStatus}`}>
              <span className={`status-dot ${apiStatus}`} />
              {apiStatus === "connected"
                ? "API Connected"
                : apiStatus === "checking"
                  ? "Checking API"
                  : "API Offline"}
            </span>

            <button
              className="icon-button"
              title="Refresh API and case list"
              onClick={() => {
                checkHealth();
                refreshCases();
              }}
            >
              <Icon name="refresh" />
            </button>
          </div>
        </header>

        {error && (
          <div className="message error-message">
            <Icon name="alert" size={17} />
            <span>{error}</span>
            <button onClick={() => setError("")}>Dismiss</button>
          </div>
        )}

        {notice && (
          <div className="message success-message">
            <Icon name="check" size={17} />
            <span>{notice}</span>
            <button onClick={() => setNotice("")}>Dismiss</button>
          </div>
        )}

        <section className="stats-grid">
          <StatCard
            label="Events analyzed"
            value={activeCase?.event_count ?? events.length}
            caption={activeCase ? activeCase.filename : "Run an analysis to begin"}
            icon="file"
            tone="teal"
          />
          <StatCard
            label="Flagged findings"
            value={findings.length}
            caption="Events requiring review"
            icon="alert"
            tone="amber"
          />
          <StatCard
            label="High / critical"
            value={highCritical}
            caption="Event-level severity"
            icon="shield"
            tone="rose"
          />
          <StatCard
            label="Correlated findings"
            value={groupedFlagged}
            caption="Group score ≥ 40"
            icon="search"
            tone="violet"
          />
        </section>

        <section id="upload-section" className="panel upload-panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">START HERE</span>
              <h2>Analyze cloud evidence</h2>
              <p>
                Upload a CSV log export or run the built-in demo dataset.
              </p>
            </div>

            <button
              className="button button-secondary"
              onClick={runDemo}
              disabled={busy}
            >
              <Icon name="shield" size={16} />
              {busy ? "Analyzing…" : "Run demo analysis"}
            </button>
          </div>

          <div
            className={`dropzone ${dragging ? "dragging" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
          >
            <div className="upload-icon">
              <Icon name="upload" size={23} />
            </div>

            <div className="drop-copy">
              <strong>Drop your CSV log file here</strong>
              <span>
                or select a file from your computer · CSV only · 10 MB
                maximum
              </span>
            </div>

            <label
              className={`button button-primary ${busy ? "disabled" : ""}`}
            >
              <Icon name="file" size={16} />
              Choose CSV
              <input
                type="file"
                accept=".csv,text/csv"
                disabled={busy}
                onChange={(event) => {
                  analyzeFile(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </label>
          </div>

          <div className="upload-footnote">
            <span>
              <Icon name="shield" size={14} /> SHA-256 hash calculated on
              upload
            </span>
            <span>
              <Icon name="file" size={14} /> Parsed event records saved to
              local SQLite
            </span>
            <span className="warning-note">
              Original uploaded file is not archived
            </span>
          </div>
        </section>

        <section className="section-block">
          <div className="section-title-row">
            <div>
              <span className="section-kicker">CORRELATION ENGINE</span>
              <h2>Evidence storyline</h2>
              <p>
                Groups of flagged events sharing the same username and source
                IP.
              </p>
            </div>
            <span className="subtle-count">
              {storylines.length}{" "}
              {storylines.length === 1 ? "group" : "groups"}
            </span>
          </div>

          {!activeCase ? (
            <div className="empty-state">
              <div className="empty-symbol">
                <Icon name="search" size={22} />
              </div>
              <strong>No investigation selected</strong>
              <p>
                Run the demo analysis to view correlated activity and group
                risk scores.
              </p>
            </div>
          ) : storylines.length === 0 ? (
            <div className="empty-state compact">
              <strong>No correlated groups found</strong>
              <p>
                At least two flagged events with matching username and source
                IP are needed for a storyline.
              </p>
            </div>
          ) : (
            <div className="storyline-grid">
              {storylines.map((story, index) => {
                const breakdown = getCorrelationBreakdown(story);

                return (
                  <article
                    className={`story-card ${
                      topCorrelation &&
                      story.username === topCorrelation.username &&
                      story.source_ip === topCorrelation.source_ip
                        ? "top-story"
                        : ""
                    }`}
                    key={`${story.username}-${story.source_ip}-${index}`}
                  >
                    <div className="story-head">
                      <div className="avatar">
                        {String(story.username || "?")
                          .slice(0, 1)
                          .toUpperCase()}
                      </div>
                      <div className="story-identity">
                        <strong>{story.username}</strong>
                        <span>{story.source_ip}</span>
                      </div>
                      <Badge level={story.correlation_level}>
                        {story.correlation_level}
                      </Badge>
                    </div>

                    <div className="score-row">
                      <div>
                        <span className="score-label">
                          CORRELATION RISK
                        </span>
                        <div className="score-number">
                          {story.correlation_score ?? 0}
                          <small>/100</small>
                        </div>
                      </div>

                      <div
                        className="score-ring"
                        style={{
                          "--score": `${Math.max(
                            0,
                            Math.min(
                              100,
                              Number(story.correlation_score || 0)
                            )
                          )}%`,
                        }}
                      >
                        <span>{story.correlation_score ?? 0}</span>
                      </div>
                    </div>

                    <div className="score-track">
                      <span
                        className={levelClass(story.correlation_level)}
                        style={{
                          width: `${Math.max(
                            0,
                            Math.min(
                              100,
                              Number(story.correlation_score || 0)
                            )
                          )}%`,
                        }}
                      />
                    </div>

                    <div className="story-events">
                      {(story.events || []).map((event, eventIndex) => (
                        <div
                          className="story-event"
                          key={`${event.id}-${eventIndex}`}
                        >
                          <div className="event-line-dot" />
                          <div className="story-event-copy">
                            <span>
                              {event.timestamp || "Time unavailable"}
                            </span>
                            <strong>{event.event_type}</strong>
                          </div>
                          <Badge level={event.severity}>
                            {event.severity}
                          </Badge>
                        </div>
                      ))}
                    </div>

                    <div className="score-breakdown">
                      <div className="breakdown-heading">
                        <strong>Score breakdown</strong>
                        <span>
                          {story.correlation_score ?? breakdown.total}/100
                        </span>
                      </div>

                      <div className="breakdown-items">
                        {breakdown.items.map((item) => (
                          <div
                            className={`breakdown-item ${
                              item.points > 0 ? "has-points" : "no-points"
                            }`}
                            key={item.label}
                            title={item.description}
                          >
                            <span>{item.label}</span>
                            <strong>
                              {item.points > 0 ? `+${item.points}` : "—"}
                            </strong>
                          </div>
                        ))}
                      </div>

                      <div className="breakdown-footnote">
                        Points are added once per signal and capped at 100.
                        Hover over a row for its explanation.
                      </div>
                    </div>

                    <div className="story-reason">
                      <Icon name="alert" size={15} />
                      <span>
                        {(story.reasons || [])[0] ||
                          "Related flagged events need analyst review."}
                      </span>
                    </div>
                  </article>
                );
              })}
            </div>
          )}

          <div className="scoring-note">
            <Icon name="file" size={15} />
            <span>
              Correlation score is an investigation-priority heuristic based
              on event group size, event types, and sequence. It is not a
              probability or proof of compromise.
            </span>
          </div>
        </section>

        <section
          id="findings-section"
          className="section-block findings-layout"
        >
          <div className="findings-main">
            <div className="section-title-row">
              <div>
                <span className="section-kicker">EVENT REVIEW</span>
                <h2>Flagged findings</h2>
                <p>
                  Review individual event-level detections and their group
                  correlation score.
                </p>
              </div>
              <button
                className="button button-secondary"
                onClick={downloadReport}
                disabled={!activeCase}
              >
                <Icon name="download" size={16} /> Export report
              </button>
            </div>

            <div className="table-toolbar">
              <div className="search-box">
                <Icon name="search" size={16} />
                <input
                  aria-label="Search findings"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search user, IP, event…"
                />
              </div>

              <select
                aria-label="Filter by severity"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              >
                <option>All</option>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
              </select>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>EVENT</th>
                    <th>IDENTITY / IP</th>
                    <th>SEVERITY</th>
                    <th>GROUP RISK</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="table-empty">
                        {activeCase
                          ? "No findings match this filter."
                          : "Run an analysis to populate findings."}
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map((item) => {
                      const isSelected =
                        String(item.id ?? item.event_id) ===
                        String(selectedFindingId);

                      return (
                        <tr
                          className={isSelected ? "selected-row" : ""}
                          key={
                            item.finding_id || item.id || item.event_id
                          }
                          onClick={() =>
                            setSelectedFindingId(
                              item.id ?? item.event_id
                            )
                          }
                        >
                          <td>
                            <strong className="event-name">
                              {item.event_type ||
                                item.event_name ||
                                "unknown_event"}
                            </strong>
                            <span className="table-sub">
                              {item.timestamp || "—"}
                            </span>
                          </td>

                          <td>
                            <strong className="identity-name">
                              {item.username || "unknown"}
                            </strong>
                            <span className="table-sub mono">
                              {item.source_ip || "unknown IP"}
                            </span>
                          </td>

                          <td>
                            <Badge level={item.severity}>
                              {item.severity || "Low"}
                            </Badge>
                            <span className="table-sub">
                              Score {item.score ?? 0}/100
                            </span>
                          </td>

                          <td>
                            <div className="group-risk-cell">
                              <strong>
                                {item.correlation_score ?? 0}
                              </strong>
                              <span>/100</span>
                              <Badge
                                level={
                                  item.correlation_level || "Uncorrelated"
                                }
                              >
                                {item.correlation_level || "Uncorrelated"}
                              </Badge>
                            </div>
                          </td>

                          <td>
                            <button
                              className="inspect-button"
                              aria-label={`Inspect ${
                                item.event_type || item.event_name
                              }`}
                              onClick={(event) => {
                                event.stopPropagation();
                                setSelectedFindingId(
                                  item.id ?? item.event_id
                                );
                              }}
                            >
                              <Icon name="chevron" size={18} />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            <div className="table-bottom">
              <span>
                Showing {filteredFindings.length} of {findings.length} findings
              </span>
              <span>Click a row to inspect details</span>
            </div>
          </div>

          <aside className="detail-panel">
            <div className="detail-header">
              <div>
                <span className="section-kicker">ANALYST REVIEW</span>
                <h3>Finding details</h3>
              </div>
              <div className="detail-icon">
                <Icon name="file" />
              </div>
            </div>

            {!selectedFinding ? (
              <div className="detail-empty">
                Select a finding from the table to inspect its evidence and
                risk signals.
              </div>
            ) : (
              <>
                <div className="detail-event-title">
                  <strong>
                    {selectedFinding.event_type ||
                      selectedFinding.event_name ||
                      "Event"}
                  </strong>
                  <span>
                    {selectedFinding.timestamp || "Timestamp unavailable"}
                  </span>
                </div>

                <div className="detail-badges">
                  <Badge level={selectedFinding.severity}>
                    {selectedFinding.severity || "Low"} severity
                  </Badge>
                  <Badge
                    level={
                      selectedFinding.correlation_level || "Uncorrelated"
                    }
                  >
                    {selectedFinding.correlation_level || "Uncorrelated"}{" "}
                    correlation
                  </Badge>
                </div>

                <div className="detail-score-grid">
                  <div>
                    <span>Event score</span>
                    <strong>
                      {selectedFinding.score ?? 0}
                      <small>/100</small>
                    </strong>
                  </div>
                  <div>
                    <span>Group score</span>
                    <strong>
                      {selectedFinding.correlation_score ?? 0}
                      <small>/100</small>
                    </strong>
                  </div>
                </div>

                <div className="detail-fields">
                  <div>
                    <span>Username</span>
                    <strong>{selectedFinding.username || "unknown"}</strong>
                  </div>
                  <div>
                    <span>Source IP</span>
                    <strong className="mono">
                      {selectedFinding.source_ip || "unknown"}
                    </strong>
                  </div>
                  <div>
                    <span>Event source</span>
                    <strong>
                      {selectedFinding.event_source || "Not specified"}
                    </strong>
                  </div>
                  <div>
                    <span>Status</span>
                    <strong>{selectedFinding.status || "unknown"}</strong>
                  </div>
                </div>

                <div className="detail-section">
                  <h4>Detection reasons</h4>
                  {(selectedFinding.reasons || []).length ? (
                    <ul>
                      {selectedFinding.reasons.map((reason, index) => (
                        <li key={index}>{reason}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>No event-level reasons provided.</p>
                  )}
                </div>

                <div className="detail-section correlation-reasons">
                  <h4>Correlation signals</h4>
                  {(selectedFinding.correlation_reasons || []).length ? (
                    <ul>
                      {selectedFinding.correlation_reasons.map(
                        (reason, index) => (
                          <li key={index}>{reason}</li>
                        )
                      )}
                    </ul>
                  ) : (
                    <p>
                      {Number(selectedFinding.correlation_score || 0) > 0
                        ? "Related events contributed to this group score."
                        : "No related flagged event group was identified."}
                    </p>
                  )}
                </div>
              </>
            )}
          </aside>
        </section>

        <section className="section-block timeline-section">
          <div className="section-title-row">
            <div>
              <span className="section-kicker">EVENT CONTEXT</span>
              <h2>Event timeline</h2>
              <p>
                Chronological view of parsed records from the active case.
              </p>
            </div>
            <span className="subtle-count">{events.length} records</span>
          </div>

          {!activeCase ? (
            <div className="empty-state compact">
              <strong>Timeline is empty</strong>
              <p>Run an analysis to view parsed events.</p>
            </div>
          ) : (
            <div className="timeline-list">
              {events
                .slice()
                .sort(
                  (a, b) =>
                    new Date(a.timestamp || 0) -
                    new Date(b.timestamp || 0)
                )
                .slice(0, 30)
                .map((event, index) => (
                  <div
                    className={`timeline-row ${
                      event.flagged ? "is-flagged" : ""
                    }`}
                    key={`${event.id || event.event_id || index}-${
                      event.timestamp
                    }`}
                  >
                    <div className="timeline-time">
                      {event.timestamp || "Time unavailable"}
                    </div>
                    <div className="timeline-marker">
                      <span />
                    </div>
                    <div className="timeline-info">
                      <strong>
                        {event.event_type ||
                          event.event_name ||
                          "unknown_event"}
                      </strong>
                      <span>
                        {event.username || "unknown"} ·{" "}
                        {event.source_ip || "unknown IP"}
                      </span>
                    </div>
                    <div className="timeline-tags">
                      {event.flagged ? (
                        <Badge level={event.severity}>
                          {event.severity}
                        </Badge>
                      ) : (
                        <span className="normal-tag">Normal</span>
                      )}
                      {Number(event.correlation_score || 0) > 0 && (
                        <span className="correlation-mini">
                          Group {event.correlation_score}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          )}

          {events.length > 30 && (
            <p className="timeline-limit">
              Showing the first 30 chronological records in this panel.
            </p>
          )}
        </section>

        <section
          id="history-section"
          className="section-block history-section"
        >
          <div className="section-title-row">
            <div>
              <span className="section-kicker">SAVED LOCALLY</span>
              <h2>Investigation history</h2>
              <p>
                Previous CSV analyses stored in the local SQLite database.
              </p>
            </div>
            <button className="text-button" onClick={refreshCases}>
              <Icon name="refresh" size={15} /> Refresh
            </button>
          </div>

          {cases.length === 0 ? (
            <div className="empty-state compact">
              <strong>No saved investigations yet</strong>
              <p>Your first analysis will appear here.</p>
            </div>
          ) : (
            <div className="case-list">
              {cases.map((item) => (
                <button
                  className={`case-row ${
                    String(activeCase?.case_id || activeCase?.id) ===
                    String(item.id)
                      ? "current"
                      : ""
                  }`}
                  key={item.id}
                  onClick={() => loadCase(item.id)}
                >
                  <div className="case-file-icon">
                    <Icon name="file" />
                  </div>
                  <div className="case-main">
                    <strong>{item.filename}</strong>
                    <span>
                      {formatDate(item.uploaded_at)} · SHA-256{" "}
                      {shortHash(item.sha256)}
                    </span>
                  </div>
                  <div className="case-counts">
                    <span>{item.event_count} events</span>
                    <Badge
                      level={Number(item.flagged_count) > 0 ? "Medium" : "Low"}
                    >
                      {item.flagged_count} flagged
                    </Badge>
                  </div>
                  <Icon name="chevron" size={17} />
                </button>
              ))}
            </div>
          )}
        </section>

        <footer className="app-footer">
          <div className="footer-brand">
            <Logo />
            <strong>TraceLens</strong>
          </div>
          <span>
            Rule-based triage with correlation-assisted prioritization.
          </span>
          <span>Findings are leads, not conclusions.</span>
        </footer>
      </main>
    </div>
  );
}

const styles = `
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{font-family:'DM Sans',Inter,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e8edf4;background:#080d17;font-synthesis:none;text-rendering:optimizeLegibility}
*{box-sizing:border-box}
body{margin:0;background:#080d17}
button,input,select{font:inherit}
button{cursor:pointer}
.app-shell{min-height:100vh;background:#080d17;color:#e8edf4}
.sidebar{width:246px;position:fixed;inset:0 auto 0 0;background:#0b1220;border-right:1px solid #1c2839;display:flex;flex-direction:column;padding:25px 17px 16px;z-index:5}
.brand{display:flex;align-items:center;gap:11px;padding:0 8px 36px}
.logo-mark{width:44px;height:44px;flex-shrink:0}
.brand strong,.mobile-brand strong{display:block;font-family:'Space Grotesk',sans-serif;font-size:20px;letter-spacing:-.6px;color:#f7fbff}
.brand span{display:block;color:#71839c;font-size:10px;margin-top:4px;letter-spacing:.1px}
.sidebar-label,.section-kicker,.eyebrow{color:#7387a0;font-size:10px;font-weight:700;letter-spacing:1.6px}
.sidebar-label{padding:0 12px 10px}
.side-link{display:flex;align-items:center;gap:12px;width:100%;border:0;background:transparent;color:#9aaac0;text-align:left;padding:12px 13px;border-radius:9px;font-size:13px;margin:2px 0}
.side-link:hover{background:#111d2e;color:#eff7ff}
.side-link.active{background:#102a31;color:#5fe4d4;font-weight:600;box-shadow:inset 2px 0 #40d9ca}
.side-count{margin-left:auto;border:1px solid #304152;border-radius:5px;padding:2px 6px;font-size:10px}
.sidebar-spacer{flex:1}
.sidebar-note{background:linear-gradient(145deg,#111d2d,#0e1826);border:1px solid #233348;padding:14px;border-radius:11px;margin:10px 0 20px}
.note-icon{width:32px;height:32px;border-radius:8px;background:#143b3b;color:#4ce0d0;display:grid;place-items:center;margin-bottom:11px}
.sidebar-note strong{font-size:12px}
.sidebar-note p{font-size:11px;line-height:1.6;color:#8da0b8;margin:7px 0 0}
.sidebar-footer{border-top:1px solid #1d2939;padding:16px 6px 0;display:flex;align-items:center;gap:8px;color:#8ca0b8;font-size:11px}
.version{margin-left:auto;color:#53657d}
.status-dot{width:7px;height:7px;display:inline-block;border-radius:50%;background:#64748b}
.status-dot.connected{background:#43d7a1;box-shadow:0 0 0 3px #43d7a11a}
.status-dot.offline{background:#fb7185}
.status-dot.checking{background:#eab308}
.main-content{margin-left:246px;max-width:1800px;padding:28px 34px 24px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:26px}
.topbar h1{font-family:'Space Grotesk',sans-serif;font-size:27px;letter-spacing:-.8px;margin:5px 0 0;color:#f2f7fc}
.topbar-actions{display:flex;align-items:center;gap:11px}
.api-pill{display:flex;align-items:center;gap:8px;border:1px solid #233246;border-radius:20px;padding:9px 12px;color:#a5b6ca;font-size:11px;background:#0c1422}
.api-pill.connected{border-color:#235448;color:#7be4bc}
.icon-button{border:1px solid #243348;background:#101a29;color:#a8b8cc;width:36px;height:36px;display:grid;place-items:center;border-radius:9px}
.mobile-brand{display:none}
.stats-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;margin-bottom:21px}
.stat-card{background:#0d1523;border:1px solid #1e2c3e;border-radius:12px;padding:17px;display:flex;gap:13px;align-items:flex-start;min-width:0}
.stat-icon{width:39px;height:39px;display:grid;place-items:center;border-radius:10px;flex-shrink:0}
.stat-icon.teal{background:#133b3c;color:#4fe0d1}
.stat-icon.amber{background:#392c19;color:#f7c86c}
.stat-icon.rose{background:#3a202c;color:#ff8ca4}
.stat-icon.violet{background:#2c2451;color:#b6a7ff}
.stat-copy{min-width:0}
.stat-copy span{display:block;color:#90a3ba;font-size:11px}
.stat-copy strong{display:block;font-family:'Space Grotesk',sans-serif;font-size:27px;line-height:1.25;margin:4px 0 3px;color:#f4f8fc}
.stat-copy small{display:block;color:#60748e;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:190px}
.panel{border:1px solid #1e2c3e;border-radius:13px;background:#0d1523}
.upload-panel{padding:22px;margin-bottom:33px}
.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:20px}
.panel-heading h2,.section-title-row h2{font-family:'Space Grotesk',sans-serif;font-size:19px;letter-spacing:-.4px;margin:5px 0;color:#edf4fb}
.panel-heading p,.section-title-row p{font-size:12px;color:#8194ac;margin:5px 0 0}
.button{display:inline-flex;align-items:center;justify-content:center;gap:8px;border-radius:8px;padding:10px 13px;font-size:11px;font-weight:700;border:1px solid transparent;white-space:nowrap}
.button:disabled,.button.disabled{opacity:.55;cursor:not-allowed}
.button-primary{background:#38d5c7;color:#06201f}
.button-primary:hover{background:#62e5d9}
.button-secondary{background:#131f2e;color:#bed0e4;border-color:#2a3a4f}
.button-secondary:hover{background:#1a2a3c;color:#f3f8ff}
.button input{display:none}
.dropzone{border:1px dashed #30465a;border-radius:11px;background:#0b1320;padding:19px 18px;display:flex;align-items:center;gap:14px;transition:.2s}
.dropzone.dragging{border-color:#38d5c7;background:#0e242a}
.upload-icon{width:43px;height:43px;display:grid;place-items:center;color:#49dccf;background:#133a3c;border-radius:10px;flex-shrink:0}
.drop-copy{display:flex;flex-direction:column;gap:5px;min-width:0;flex:1}
.drop-copy strong{font-size:12px;color:#dae6f2}
.drop-copy span{font-size:10px;color:#7489a3}
.upload-footnote{display:flex;align-items:center;gap:17px;flex-wrap:wrap;margin-top:13px;color:#71869f;font-size:10px}
.upload-footnote span{display:flex;align-items:center;gap:6px}
.warning-note{color:#c69c61!important}
.section-block{margin-bottom:35px}
.section-title-row{display:flex;justify-content:space-between;align-items:flex-end;gap:15px;margin-bottom:16px}
.subtle-count{border:1px solid #26364a;background:#0e1725;color:#8ca0b8;font-size:10px;padding:6px 9px;border-radius:7px;white-space:nowrap}
.storyline-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.story-card{background:#0d1523;border:1px solid #243349;border-radius:12px;padding:17px;min-width:0}
.story-card.top-story{border-color:#286b69;box-shadow:0 0 0 1px #164c4a inset}
.story-head{display:flex;align-items:center;gap:10px}
.avatar{height:35px;width:35px;border-radius:10px;display:grid;place-items:center;background:#193844;color:#6ae5db;font-weight:700;font-size:13px}
.story-identity{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1}
.story-identity strong{font-size:12px;color:#ebf2fa}
.story-identity span{font-family:ui-monospace,monospace;font-size:10px;color:#7b91aa}
.badge{display:inline-flex;align-items:center;border-radius:5px;padding:4px 7px;font-size:9px;font-weight:700;letter-spacing:.1px;white-space:nowrap;border:1px solid transparent}
.badge.critical{background:#4a1e2b;color:#ff9aaf;border-color:#6e2b3c}
.badge.high{background:#482a20;color:#ffb08c;border-color:#6e3b2a}
.badge.medium{background:#41351e;color:#f0cf79;border-color:#5b4a28}
.badge.low{background:#17352e;color:#7ce0b5;border-color:#245243}
.badge.muted{background:#1d2938;color:#9aaabd;border-color:#2b3b4e}
.score-row{display:flex;align-items:center;justify-content:space-between;margin:19px 1px 10px}
.score-label{color:#8296ae;font-size:9px;letter-spacing:1.2px;font-weight:700}
.score-number{font-family:'Space Grotesk',sans-serif;font-size:28px;line-height:1.3;color:#eef6fc;font-weight:700}
.score-number small,.detail-score-grid strong small{font-family:'DM Sans',sans-serif;font-size:11px;color:#7489a0;font-weight:500;margin-left:3px}
.score-ring{width:52px;height:52px;border-radius:50%;background:conic-gradient(#46d8c8 var(--score),#1d2b3e 0);display:grid;place-items:center;position:relative}
.score-ring:before{content:"";position:absolute;inset:5px;border-radius:50%;background:#0d1523}
.score-ring span{position:relative;font-family:'Space Grotesk',sans-serif;font-size:13px;font-weight:700}
.score-track{height:4px;border-radius:5px;background:#202d3e;overflow:hidden}
.score-track span{height:100%;display:block;border-radius:5px}
.score-track span.critical{background:#ff718b}
.score-track span.high{background:#f49b6e}
.score-track span.medium{background:#e6c365}
.score-track span.low{background:#4bd0a2}
.story-events{margin-top:17px}
.story-event{display:flex;align-items:center;gap:10px;position:relative;padding:9px 0;border-bottom:1px solid #1b2839}
.story-event:last-child{border-bottom:0}
.event-line-dot{height:7px;width:7px;border-radius:50%;background:#4ad8cb;box-shadow:0 0 0 3px #4ad8cb1a;flex-shrink:0}
.story-event-copy{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1}
.story-event-copy span{color:#70859f;font-size:9px}
.story-event-copy strong{font-size:11px;color:#d8e4f1}

.score-breakdown {
  margin-top: 12px;
  padding: 11px 12px;
  background: #0b1420;
  border: 1px solid #223247;
  border-radius: 8px;
}

.breakdown-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 7px;
}

.breakdown-heading strong {
  font-size: 10px;
  letter-spacing: .35px;
  text-transform: uppercase;
  color: #aabbd0;
}

.breakdown-heading span {
  font-family: "Space Grotesk", sans-serif;
  font-size: 12px;
  font-weight: 700;
  color: #61ded2;
}

.breakdown-items {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.breakdown-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 5px 0;
  border-top: 1px solid #1a293b;
  font-size: 10px;
}

.breakdown-item span {
  color: #8095ad;
}

.breakdown-item strong {
  min-width: 30px;
  text-align: right;
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}

.breakdown-item.has-points strong {
  color: #66dfd3;
}

.breakdown-item.no-points strong {
  color: #53677f;
}

.breakdown-footnote {
  margin-top: 6px;
  font-size: 9px;
  line-height: 1.45;
  color: #637992;
}

.story-reason{display:flex;align-items:flex-start;gap:7px;padding:10px;background:#121e2d;border:1px solid #223247;border-radius:7px;color:#9cb0c7;font-size:10px;line-height:1.55;margin-top:12px}
.story-reason svg{color:#e9bd64;flex-shrink:0;margin-top:1px}
.scoring-note{display:flex;gap:8px;align-items:flex-start;color:#758aa3;font-size:10px;line-height:1.6;margin-top:12px}
.scoring-note svg{color:#5f7792;flex-shrink:0}
.findings-layout{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(270px,.85fr);gap:17px;align-items:start}
.findings-main{min-width:0}
.findings-main>.section-title-row{align-items:flex-end}
.table-toolbar{display:flex;gap:10px;margin-bottom:11px}
.search-box{flex:1;display:flex;align-items:center;gap:8px;padding:0 11px;border:1px solid #26364a;background:#0d1523;border-radius:8px;color:#7187a2}
.search-box input{border:0;outline:0;background:transparent;color:#e5eef7;width:100%;padding:10px 0;font-size:11px}
.search-box input::placeholder{color:#647891}
.table-toolbar select{border:1px solid #26364a;background:#0d1523;color:#b8c8dc;border-radius:8px;padding:0 10px;font-size:10px;outline:none}
.table-wrap{overflow:auto;border:1px solid #1f2d40;border-radius:10px;background:#0c1421}
.table-wrap table{width:100%;border-collapse:collapse;text-align:left;min-width:630px}
.table-wrap th{background:#101a29;color:#6f849e;font-size:9px;letter-spacing:.8px;text-transform:uppercase;font-weight:700;padding:12px 11px}
.table-wrap td{padding:13px 11px;border-top:1px solid #1b293b;vertical-align:middle}
.table-wrap tbody tr{cursor:pointer;transition:background .15s}
.table-wrap tbody tr:hover{background:#111e2e}
.table-wrap tbody tr.selected-row{background:#10282e;box-shadow:inset 2px 0 #42d7ca}
.event-name,.identity-name{display:block;font-size:11px;color:#dce7f3;font-weight:600}
.table-sub{display:block;margin-top:5px;font-size:9px;color:#768ba4;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.group-risk-cell{display:flex;align-items:center;flex-wrap:wrap;gap:5px}
.group-risk-cell>strong{font-family:'Space Grotesk',sans-serif;font-size:15px;color:#e1edf8}
.group-risk-cell>span{font-size:9px;color:#71859e;margin-left:-4px}
.inspect-button{display:grid;place-items:center;width:25px;height:25px;border:1px solid #26384c;background:#111d2c;color:#7991ac;border-radius:6px}
.table-empty{text-align:center;color:#788ca5;padding:28px!important;font-size:11px}
.table-bottom{display:flex;justify-content:space-between;gap:8px;padding:10px 3px;color:#657a94;font-size:9px}
.detail-panel{background:#0d1523;border:1px solid #243349;border-radius:11px;padding:17px;min-width:0}
.detail-header{display:flex;align-items:center;justify-content:space-between;padding-bottom:14px;border-bottom:1px solid #1e2b3c}
.detail-header h3{font-family:'Space Grotesk',sans-serif;font-size:16px;margin:5px 0 0}
.detail-icon{height:32px;width:32px;border-radius:8px;background:#17263a;color:#88a0bc;display:grid;place-items:center}
.detail-event-title{padding:16px 0 11px;display:flex;flex-direction:column;gap:5px}
.detail-event-title strong{font-size:14px;color:#f0f6fc;overflow-wrap:anywhere}
.detail-event-title span{font-size:10px;color:#7e93ac}
.detail-badges{display:flex;flex-wrap:wrap;gap:6px}
.detail-score-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin:16px 0}
.detail-score-grid>div{border:1px solid #243449;background:#101b2a;border-radius:8px;padding:11px}
.detail-score-grid span{font-size:9px;color:#8296af;display:block}
.detail-score-grid strong{font-family:'Space Grotesk',sans-serif;display:block;font-size:23px;margin-top:4px}
.detail-fields{border-top:1px solid #202c3d;border-bottom:1px solid #202c3d;padding:6px 0}
.detail-fields>div{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;padding:7px 0}
.detail-fields span{font-size:10px;color:#71869f}
.detail-fields strong{font-size:10px;text-align:right;color:#c7d5e5;overflow-wrap:anywhere;max-width:65%}
.detail-section{margin-top:15px}
.detail-section h4{font-size:10px;letter-spacing:.5px;color:#b4c4d7;text-transform:uppercase;margin:0 0 8px}
.detail-section ul{padding-left:17px;margin:0}
.detail-section li{font-size:10px;color:#95a9c0;line-height:1.55;margin:6px 0}
.detail-section p,.detail-empty{font-size:10px;color:#7d92aa;line-height:1.6}
.correlation-reasons{background:#101b29;border:1px solid #243348;padding:12px;border-radius:8px}
.correlation-reasons h4{color:#65dcd1}
.timeline-section{margin-top:4px}
.timeline-list{background:#0d1523;border:1px solid #203046;border-radius:11px;padding:5px 17px}
.timeline-row{display:grid;grid-template-columns:155px 18px minmax(130px,1fr) auto;gap:12px;align-items:center;min-height:54px;border-bottom:1px solid #1c2a3b}
.timeline-row:last-child{border-bottom:0}
.timeline-time{font-size:9px;color:#758ba4;font-variant-numeric:tabular-nums}
.timeline-marker{height:100%;position:relative;display:grid;place-items:center}
.timeline-marker:before{content:"";position:absolute;top:0;bottom:0;width:1px;background:#26374b}
.timeline-row:first-child .timeline-marker:before{top:50%}
.timeline-row:last-child .timeline-marker:before{bottom:50%}
.timeline-marker span{height:7px;width:7px;background:#68809b;border-radius:50%;position:relative;z-index:1}
.timeline-row.is-flagged .timeline-marker span{background:#ebbd61;box-shadow:0 0 0 3px #ebbd611c}
.timeline-info{display:flex;flex-direction:column;gap:4px;min-width:0}
.timeline-info strong{font-size:11px;color:#dce6f2;overflow-wrap:anywhere}
.timeline-info span{font-size:9px;color:#778ca5;overflow-wrap:anywhere}
.timeline-tags{display:flex;align-items:center;gap:7px}
.normal-tag{font-size:9px;color:#7191a2}
.correlation-mini{font-size:9px;color:#58d7cb;background:#123233;border:1px solid #1f4d4d;border-radius:4px;padding:4px 5px;white-space:nowrap}
.timeline-limit{font-size:10px;color:#70859e;margin:10px 0 0}
.history-section{margin-top:35px}
.text-button{display:flex;align-items:center;gap:6px;background:transparent;border:0;color:#79bfb8;font-size:10px}
.case-list{border:1px solid #203046;border-radius:11px;overflow:hidden}
.case-row{width:100%;display:flex;align-items:center;gap:12px;text-align:left;padding:14px 16px;border:0;border-bottom:1px solid #1d2a3b;background:#0d1523;color:#dbe5f1}
.case-row:last-child{border-bottom:0}
.case-row:hover,.case-row.current{background:#102329}
.case-file-icon{height:34px;width:34px;display:grid;place-items:center;border-radius:8px;color:#71dbd0;background:#153236;flex-shrink:0}
.case-main{display:flex;flex-direction:column;gap:5px;min-width:0;flex:1}
.case-main strong{font-size:11px;overflow-wrap:anywhere}
.case-main span{font-size:9px;color:#7187a1;overflow-wrap:anywhere}
.case-counts{display:flex;align-items:center;gap:12px;color:#8397af;font-size:9px;white-space:nowrap}
.case-row>svg:last-child{color:#617791;flex-shrink:0}
.empty-state{border:1px dashed #293b51;border-radius:11px;background:#0c1421;padding:32px 20px;display:flex;align-items:center;flex-direction:column;text-align:center;color:#8196af}
.empty-state.compact{padding:22px}
.empty-symbol{width:42px;height:42px;display:grid;place-items:center;border-radius:12px;background:#142539;color:#6fdcd2;margin-bottom:11px}
.empty-state strong{font-size:12px;color:#d3deeb}
.empty-state p{font-size:10px;line-height:1.6;margin:7px 0 0;max-width:460px}
.message{display:flex;align-items:center;gap:9px;padding:11px 13px;border-radius:8px;margin:-10px 0 18px;font-size:11px}
.message span{flex:1}
.message button{border:0;background:transparent;color:inherit;font-size:10px;text-decoration:underline}
.error-message{background:#361b27;border:1px solid #653042;color:#ffb2c0}
.success-message{background:#102e2b;border:1px solid #20534b;color:#8de5c4}
.app-footer{border-top:1px solid #1e2a3a;display:flex;align-items:center;gap:18px;padding:18px 0 0;margin-top:38px;color:#596f88;font-size:9px}
.footer-brand{display:flex;align-items:center;gap:6px;color:#9cacc0}
.footer-brand .logo-mark{width:22px;height:22px}
.footer-brand strong{font-family:'Space Grotesk',sans-serif;font-size:12px}
.app-footer>span:last-child{margin-left:auto}
.disabled{pointer-events:none}

@media(max-width:1200px){
  .main-content{padding:25px 22px}
  .stats-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .findings-layout{grid-template-columns:minmax(0,1fr)}
  .detail-panel{max-width:none}
  .storyline-grid{grid-template-columns:1fr}
}

@media(max-width:760px){
  .sidebar{display:none}
  .main-content{margin-left:0;padding:18px 13px 22px}
  .topbar{align-items:flex-start;flex-wrap:wrap}
  .topbar h1{font-size:22px}
  .topbar-actions{margin-left:auto}
  .mobile-brand{display:flex;align-items:center;gap:8px;width:100%;margin-bottom:5px}
  .mobile-brand .logo-mark{width:29px;height:29px}
  .mobile-brand strong{font-size:17px}
  .api-pill{font-size:0;padding:8px}
  .api-pill .status-dot{margin:0}
  .panel-heading{align-items:flex-start;flex-direction:column}
  .panel-heading .button{align-self:stretch}
  .dropzone{flex-wrap:wrap}
  .drop-copy{flex-basis:calc(100% - 60px)}
  .dropzone>.button{width:100%}
  .upload-footnote{gap:9px;flex-direction:column;align-items:flex-start}
  .stats-grid{gap:9px}
  .stat-card{padding:12px;gap:9px}
  .stat-icon{width:32px;height:32px}
  .stat-copy strong{font-size:23px}
  .stat-copy span{font-size:10px}
  .stat-copy small{font-size:9px}
  .section-title-row{align-items:flex-start}
  .section-title-row h2{font-size:17px}
  .section-title-row p{line-height:1.5}
  .findings-main>.section-title-row{flex-direction:column;align-items:flex-start}
  .timeline-row{grid-template-columns:1fr 14px minmax(0,1fr);gap:8px;padding:10px 0}
  .timeline-time{font-size:8px}
  .timeline-tags{grid-column:3;flex-wrap:wrap}
  .case-row{gap:9px;padding:12px 10px}
  .case-counts{flex-direction:column;align-items:flex-start;gap:4px}
  .case-main span{font-size:8px}
  .app-footer{flex-wrap:wrap;gap:9px}
  .app-footer>span:last-child{margin-left:0}
  .table-bottom{flex-wrap:wrap}
  .detail-fields strong{max-width:58%}
}
`;
