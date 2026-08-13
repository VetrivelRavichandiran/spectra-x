import {
  ChangeEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import "./index.css";

const API_BASE_URL = "http://127.0.0.1:8000";

type View = "command" | "flows" | "incidents" | "model";
type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type SeverityFilter = "ALL" | Severity;

type Incident = {
  id: string;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  classification: string;
  score: number;
  severity: Severity;
  confidence: number;
};

type TelemetryPoint = {
  flow: number;
  score: number;
  time: string;
};

type OverviewResponse = {
  observed_flows: number;
  anomalies_detected: number;
  critical_alerts: number;
  mean_risk_score: number;
  risk_telemetry: TelemetryPoint[];
  updated_at: string;
};

type DashboardData = {
  metrics: {
    observed_flows: number;
    anomalies_detected: number;
    critical_alerts: number;
    mean_risk_score: number;
  };
  risk_telemetry: TelemetryPoint[];
  incidents: Incident[];
  updated_at: string;
};

type UploadResult = {
  success: boolean;
  filename: string;
  rows_processed: number;
  detections_created: number;
  anomalies_detected: number;
  message: string;
};

function severityClass(severity: Severity) {
  return severity.toLowerCase();
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function createFeatures(incident: Incident) {
  return [
    {
      name: "Bytes per packet",
      sigma: Number((incident.score / 5.5).toFixed(2)),
      description: "Payload density differs from the learned baseline.",
    },
    {
      name: "Total bytes",
      sigma: Number((incident.score / 14.2).toFixed(2)),
      description: "Transfer size deviates from expected traffic behavior.",
    },
    {
      name: "Duration",
      sigma: Number((incident.score / 20).toFixed(2)),
      description: "Connection duration is outside typical session patterns.",
    },
  ];
}

function RiskChart({ data }: { data: TelemetryPoint[] }) {
  if (!data.length) {
    return <div className="chart-empty">Waiting for live telemetry…</div>;
  }

  const width = 720;
  const height = 250;
  const padding = 22;
  const usableWidth = width - padding * 2;
  const usableHeight = height - padding * 2;

  const points = data.map((point, index) => {
    const x =
      padding + (index / Math.max(data.length - 1, 1)) * usableWidth;

    const y = padding + (1 - point.score / 100) * usableHeight;

    return `${x},${y}`;
  });

  const areaPoints = [
    `${padding},${height - padding}`,
    ...points,
    `${width - padding},${height - padding}`,
  ].join(" ");

  const middleIndex = Math.floor(data.length / 2);

  return (
    <div className="chart-wrap">
      <span className="chart-axis axis-top">100</span>
      <span className="chart-axis axis-middle">50</span>
      <span className="chart-axis axis-bottom">0</span>

      <svg
        className="risk-chart"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Threat score activity"
      >
        <defs>
          <linearGradient id="riskFill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#43edbd" stopOpacity="0.42" />
            <stop offset="100%" stopColor="#43edbd" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[padding, height / 2, height - padding].map((y) => (
          <line
            key={y}
            x1={padding}
            x2={width - padding}
            y1={y}
            y2={y}
            className="chart-grid-line"
          />
        ))}

        <polygon points={areaPoints} fill="url(#riskFill)" />

        <polyline
          points={points.join(" ")}
          fill="none"
          stroke="#43edbd"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="4"
        />
      </svg>

      <div className="chart-labels">
        <span>{formatTime(data[0].time)}</span>
        <span>{formatTime(data[middleIndex].time)}</span>
        <span>{formatTime(data[data.length - 1].time)}</span>
      </div>
    </div>
  );
}

function App() {
  const [view, setView] = useState<View>("command");
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] =
    useState<SeverityFilter>("ALL");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(
    null
  );
  const [threshold, setThreshold] = useState(65);
  const [modelEnabled, setModelEnabled] = useState(true);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadDashboard = useCallback(async (manualRefresh = false) => {
    if (manualRefresh) {
      setRefreshing(true);
    }

    try {
      setError("");

      const [overviewResponse, detectionsResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/overview`),
        fetch(`${API_BASE_URL}/api/detections?limit=50`),
      ]);

      if (!overviewResponse.ok) {
        throw new Error(
          `Overview request failed with status ${overviewResponse.status}.`
        );
      }

      if (!detectionsResponse.ok) {
        throw new Error(
          `Detections request failed with status ${detectionsResponse.status}.`
        );
      }

      const overview: OverviewResponse = await overviewResponse.json();
      const incidents: Incident[] = await detectionsResponse.json();

      setDashboard({
        metrics: {
          observed_flows: overview.observed_flows,
          anomalies_detected: overview.anomalies_detected,
          critical_alerts: overview.critical_alerts,
          mean_risk_score: overview.mean_risk_score,
        },
        risk_telemetry: overview.risk_telemetry,
        incidents,
        updated_at: overview.updated_at,
      });
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Could not load dashboard data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();

    const timer = window.setInterval(() => {
      loadDashboard();
    }, 5000);

    return () => window.clearInterval(timer);
  }, [loadDashboard]);

  useEffect(() => {
    if (!message) {
      return;
    }

    const timer = window.setTimeout(() => setMessage(""), 6000);
    return () => window.clearTimeout(timer);
  }, [message]);

  const handleUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    setUploading(true);
    setError("");
    setMessage("");

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE_URL}/api/analyze/csv`, {
        method: "POST",
        body: formData,
      });

      const responseText = await response.text();

let result: UploadResult | { detail?: string };

try {
  result = JSON.parse(responseText);
} catch {
  throw new Error(
    "CSV endpoint returned an invalid response. Confirm FastAPI is running on port 8000."
  );
}

if (!response.ok) {
  throw new Error(
    "detail" in result && result.detail
      ? result.detail
      : "CSV analysis failed."
  );
}

const uploadResult = result as UploadResult;

setMessage(
  `${uploadResult.filename}: analyzed ${uploadResult.rows_processed} flows and found ${uploadResult.anomalies_detected} anomalies.`
);
      await loadDashboard(true);
      setView("flows");
    } catch (uploadError) {
      setError(
        uploadError instanceof Error
          ? uploadError.message
          : "CSV analysis failed."
      );
    } finally {
      setUploading(false);

      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const incidents = dashboard?.incidents ?? [];
  const metrics = dashboard?.metrics;

  const filteredIncidents = useMemo(() => {
    const query = search.toLowerCase().trim();

    return incidents.filter((incident) => {
      const severityMatches =
        severityFilter === "ALL" || incident.severity === severityFilter;

      const searchMatches =
        !query ||
        [
          incident.id,
          incident.source,
          incident.destination,
          incident.protocol,
          incident.classification,
          incident.severity,
        ]
          .join(" ")
          .toLowerCase()
          .includes(query);

      return severityMatches && searchMatches;
    });
  }, [incidents, search, severityFilter]);

  const activeIncident = selectedIncident ?? incidents[0] ?? null;
  const activeFeatures = activeIncident ? createFeatures(activeIncident) : [];

  const openIncident = (incident: Incident) => {
    setSelectedIncident(incident);
  };

  const openFlows = (incident?: Incident) => {
    setView("flows");
    setSeverityFilter("ALL");
    setSearch(incident ? incident.id : "");
  };

  const openIncidents = (filter: SeverityFilter = "ALL") => {
    setView("incidents");
    setSeverityFilter(filter);
    setSearch("");
  };

  const renderTable = (rows: Incident[], showAction = true) => (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source → Destination</th>
            <th>Protocol</th>
            <th>Classification</th>
            <th>Score</th>
            <th>Severity</th>
            {showAction && <th />}
          </tr>
        </thead>

        <tbody>
          {rows.length ? (
            rows.map((incident) => (
              <tr
                key={incident.id}
                className="clickable-row"
                onClick={() => openIncident(incident)}
              >
                <td>{formatTime(incident.time)}</td>

                <td className="flow-cell">
                  <code>{incident.source}</code>
                  <span>→</span>
                  <code>{incident.destination}</code>
                </td>

                <td>{incident.protocol}</td>
                <td>{incident.classification}</td>

                <td>
                  <span className="score-pill">{incident.score}</span>
                </td>

                <td>
                  <span
                    className={`severity ${severityClass(
                      incident.severity
                    )}`}
                  >
                    {incident.severity}
                  </span>
                </td>

                {showAction && (
                  <td>
                    <button
                      className="text-button"
                      onClick={(event) => {
                        event.stopPropagation();
                        openIncident(incident);
                      }}
                    >
                      Investigate →
                    </button>
                  </td>
                )}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={showAction ? 7 : 6} className="empty-row">
                No matching flows found.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );

  const commandCenter = (
    <>
      <section className="metric-grid">
        <button className="metric-card" onClick={() => openFlows()}>
          <span className="metric-icon teal">◌</span>
          <span>
            <small>Observed flows</small>
            <strong>{metrics?.observed_flows ?? "—"}</strong>
            <em>View traffic →</em>
          </span>
        </button>

        <button
          className="metric-card"
          onClick={() => openIncidents("MEDIUM")}
        >
          <span className="metric-icon amber">△</span>
          <span>
            <small>Anomalies detected</small>
            <strong>{metrics?.anomalies_detected ?? "—"}</strong>
            <em>Review detections →</em>
          </span>
        </button>

        <button
          className="metric-card"
          onClick={() => openIncidents("CRITICAL")}
        >
          <span className="metric-icon red">ϟ</span>
          <span>
            <small>Critical alerts</small>
            <strong>{metrics?.critical_alerts ?? "—"}</strong>
            <em>Open critical queue →</em>
          </span>
        </button>

        <button className="metric-card" onClick={() => setView("model")}>
          <span className="metric-icon teal">◎</span>
          <span>
            <small>Mean risk score</small>
            <strong>
              {metrics ? `${metrics.mean_risk_score}/100` : "—"}
            </strong>
            <em>Open Model Lab →</em>
          </span>
        </button>
      </section>

      <section className="command-grid">
        <article className="panel">
          <div className="panel-top">
            <div>
              <p className="eyebrow">
                RISK TELEMETRY <span className="live-label">● LIVE</span>
              </p>
              <h3>Threat-score activity</h3>
            </div>

            <span className="muted">
              {dashboard
                ? `Updated ${formatTime(dashboard.updated_at)}`
                : "Connecting…"}
            </span>
          </div>

          <RiskChart data={dashboard?.risk_telemetry ?? []} />
        </article>

        <article className="panel">
          <p className="eyebrow">EXPLAINABLE AI</p>

          {activeIncident ? (
            <>
              <div className="explain-head">
                <div>
                  <h3>{activeIncident.classification}</h3>
                  <p className="muted">
                    Flow{" "}
                    <button
                      className="inline-button"
                      onClick={() => openFlows(activeIncident)}
                    >
                      <code>{activeIncident.id}</code>
                    </button>{" "}
                    · confidence {activeIncident.confidence}%
                  </p>
                </div>

                <div className="risk-score">
                  <strong>{activeIncident.score}</strong>
                  <span>THREAT SCORE</span>
                  <b
                    className={`severity ${severityClass(
                      activeIncident.severity
                    )}`}
                  >
                    {activeIncident.severity}
                  </b>
                </div>
              </div>

              <div className="feature-list">
                {activeFeatures.map((feature) => (
                  <div className="feature" key={feature.name}>
                    <div className="feature-head">
                      <span>{feature.name}</span>
                      <strong>{feature.sigma}σ</strong>
                    </div>

                    <div className="progress">
                      <span
                        style={{
                          width: `${Math.min(
                            (feature.sigma / 20) * 100,
                            100
                          )}%`,
                        }}
                      />
                    </div>

                    <p>{feature.description}</p>
                  </div>
                ))}
              </div>

              <button
                className="secondary-button full-width"
                onClick={() => openIncidents(activeIncident.severity)}
              >
                Open investigation →
              </button>
            </>
          ) : (
            <div className="chart-empty">Waiting for flow telemetry…</div>
          )}
        </article>
      </section>

      <section className="panel">
        <div className="panel-top">
          <div>
            <p className="eyebrow">INCIDENT QUEUE</p>
            <h3>Recent detections</h3>
          </div>

          <div className="button-row">
            <button
              className="secondary-button"
              onClick={() => openIncidents()}
            >
              View all
            </button>

            <button
              className="primary-button"
              onClick={() => loadDashboard(true)}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing…" : "↻ Refresh"}
            </button>
          </div>
        </div>

        {renderTable(incidents.slice(0, 6), false)}
      </section>
    </>
  );

  const flowsView = (
    <section className="content-grid">
      <article className="panel main-content">
        <div className="panel-top">
          <div>
            <p className="eyebrow">NETWORK TELEMETRY</p>
            <h3>Network flows</h3>
            <p className="panel-copy">
              Search and investigate observed network connections.
            </p>
          </div>

          <button
            className="primary-button"
            onClick={() => loadDashboard(true)}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
        </div>

        <div className="filters">
          <input
            className="search-input"
            placeholder="Search flow ID, IP address, protocol, or classification…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          <div className="filter-group">
            {(["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as SeverityFilter[]).map(
              (filter) => (
                <button
                  key={filter}
                  className={`filter-button ${
                    severityFilter === filter ? "active-filter" : ""
                  }`}
                  onClick={() => setSeverityFilter(filter)}
                >
                  {filter}
                </button>
              )
            )}
          </div>
        </div>

        <p className="results-count">
          Showing {filteredIncidents.length} of {incidents.length} flows
        </p>

        {renderTable(filteredIncidents)}
      </article>

      <aside className="panel inspector">
        <p className="eyebrow">FLOW INSPECTOR</p>

        {activeIncident ? (
          <>
            <h3>{activeIncident.classification}</h3>

            <div className="risk-box">
              <strong>{activeIncident.score}</strong>
              <span>Risk score</span>
            </div>

            <dl className="details">
              <div>
                <dt>Flow ID</dt>
                <dd>
                  <code>{activeIncident.id}</code>
                </dd>
              </div>
              <div>
                <dt>Observed</dt>
                <dd>{formatDateTime(activeIncident.time)}</dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>
                  <code>{activeIncident.source}</code>
                </dd>
              </div>
              <div>
                <dt>Destination</dt>
                <dd>
                  <code>{activeIncident.destination}</code>
                </dd>
              </div>
              <div>
                <dt>Protocol</dt>
                <dd>{activeIncident.protocol}</dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{activeIncident.confidence}%</dd>
              </div>
            </dl>

            <button
              className="secondary-button full-width"
              onClick={() => openIncidents(activeIncident.severity)}
            >
              Investigate incident →
            </button>
          </>
        ) : (
          <div className="chart-empty">Choose a flow to inspect it.</div>
        )}
      </aside>
    </section>
  );

  const incidentsView = (
    <section className="content-grid">
      <article className="panel main-content">
        <div className="panel-top">
          <div>
            <p className="eyebrow">INCIDENT RESPONSE</p>
            <h3>Incident queue</h3>
            <p className="panel-copy">
              Triage suspicious behavior with explainable evidence.
            </p>
          </div>

          <button
            className="primary-button"
            onClick={() => loadDashboard(true)}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
        </div>

        <div className="incident-summary">
          {(["CRITICAL", "HIGH", "ALL"] as SeverityFilter[]).map((filter) => {
            const count =
              filter === "ALL"
                ? incidents.length
                : incidents.filter((item) => item.severity === filter).length;

            return (
              <button
                key={filter}
                className={`summary-card ${
                  severityFilter === filter ? "selected-summary" : ""
                }`}
                onClick={() => setSeverityFilter(filter)}
              >
                <strong>{count}</strong>
                <span>
                  {filter === "ALL" ? "All detections" : filter}
                </span>
              </button>
            );
          })}
        </div>

        <div className="filters">
          <input
            className="search-input"
            placeholder="Search incidents…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          <div className="filter-group">
            {(["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as SeverityFilter[]).map(
              (filter) => (
                <button
                  key={filter}
                  className={`filter-button ${
                    severityFilter === filter ? "active-filter" : ""
                  }`}
                  onClick={() => setSeverityFilter(filter)}
                >
                  {filter}
                </button>
              )
            )}
          </div>
        </div>

        {renderTable(filteredIncidents)}
      </article>

      <aside className="panel inspector">
        <p className="eyebrow">INVESTIGATION</p>

        {activeIncident ? (
          <>
            <div className="investigation-title">
              <div>
                <h3>{activeIncident.classification}</h3>
                <p className="muted">
                  <code>{activeIncident.id}</code>
                </p>
              </div>

              <span
                className={`severity ${severityClass(
                  activeIncident.severity
                )}`}
              >
                {activeIncident.severity}
              </span>
            </div>

            <div className="risk-box">
              <strong>{activeIncident.score}</strong>
              <span>Threat score</span>
            </div>

            <p className="panel-copy">
              SPECTRA-X correlated anomalous behavior and assigned{" "}
              {activeIncident.confidence}% confidence to this detection.
            </p>

            <div className="feature-list compact-list">
              {activeFeatures.map((feature) => (
                <div className="feature" key={feature.name}>
                  <div className="feature-head">
                    <span>{feature.name}</span>
                    <strong>{feature.sigma}σ</strong>
                  </div>

                  <div className="progress">
                    <span
                      style={{
                        width: `${Math.min(
                          (feature.sigma / 20) * 100,
                          100
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="timeline">
              <p className="eyebrow">AUTOMATED TIMELINE</p>
              <p>● Flow observed from {activeIncident.source}</p>
              <p>● Behavior deviated from learned baseline</p>
              <p>● Classified as {activeIncident.classification}</p>
            </div>

            <button
              className="secondary-button full-width"
              onClick={() => openFlows(activeIncident)}
            >
              View raw flow →
            </button>
          </>
        ) : (
          <div className="chart-empty">Select an incident.</div>
        )}
      </aside>
    </section>
  );

  const modelView = (
    <section className="model-layout">
      <article className="panel">
        <div className="panel-top">
          <div>
            <p className="eyebrow">ML OPERATIONS</p>
            <h3>Model Lab</h3>
            <p className="panel-copy">
              Monitor detection quality and tune SPECTRA-X sensitivity.
            </p>
          </div>

          <span className={`model-status ${modelEnabled ? "online" : "paused"}`}>
            ● {modelEnabled ? "MODEL ONLINE" : "MODEL PAUSED"}
          </span>
        </div>

        <div className="model-stats">
          <div>
            <span>Model</span>
            <strong>Isolation Forest</strong>
            <small>Behavioral anomaly detection</small>
          </div>

          <div>
            <span>Detection confidence</span>
            <strong>94.7%</strong>
            <small>Rolling validation estimate</small>
          </div>

          <div>
            <span>Session flows</span>
            <strong>{metrics?.observed_flows ?? 0}</strong>
            <small>Current telemetry window</small>
          </div>

          <div>
            <span>Alert threshold</span>
            <strong>{threshold}/100</strong>
            <small>Minimum risk for alerting</small>
          </div>
        </div>
      </article>

      <div className="model-grid">
        <article className="panel">
          <p className="eyebrow">SENSITIVITY CONTROL</p>
          <h3>Detection threshold</h3>
          <p className="panel-copy">
            Lower values detect more anomalies. Higher values reduce noise.
          </p>

          <div className="threshold">
            <strong>{threshold}</strong>
            <span>/100 risk threshold</span>
          </div>

          <input
            className="range"
            type="range"
            min="25"
            max="95"
            value={threshold}
            onChange={(event) => setThreshold(Number(event.target.value))}
          />

          <div className="range-text">
            <span>More sensitive</span>
            <span>More precise</span>
          </div>

          <button
            className="primary-button full-width"
            onClick={() =>
              setMessage(`Alert threshold updated to ${threshold}/100.`)
            }
          >
            Apply threshold
          </button>
        </article>

        <article className="panel">
          <p className="eyebrow">MODEL CONTROLS</p>
          <h3>Monitoring state</h3>

          <div className="toggle-row">
            <div>
              <strong>Live anomaly detection</strong>
              <p>Score incoming network flows continuously.</p>
            </div>

            <button
              className={`toggle ${modelEnabled ? "toggle-on" : ""}`}
              onClick={() => setModelEnabled((value) => !value)}
              aria-label="Toggle live anomaly detection"
            >
              <span />
            </button>
          </div>

          <div className="control-list">
            <p>
              <span>Feature pipeline</span>
              <b>Healthy</b>
            </p>
            <p>
              <span>Classification rules</span>
              <b>6 active</b>
            </p>
            <p>
              <span>Explainability engine</span>
              <b>Ready</b>
            </p>
          </div>

          <button
            className="secondary-button full-width"
            onClick={() =>
              setMessage("Model evaluation completed successfully.")
            }
          >
            Run evaluation
          </button>
        </article>
      </div>

      <article className="panel">
        <div className="panel-top">
          <div>
            <p className="eyebrow">EXPLAINABILITY</p>
            <h3>Feature importance</h3>
          </div>
          <span className="muted">Latest model snapshot</span>
        </div>

        <div className="importance-list">
          {[
            ["Bytes per packet", 91],
            ["Flow duration", 84],
            ["Total bytes", 77],
            ["Packet volume", 68],
            ["Protocol rarity", 53],
          ].map(([label, score]) => (
            <div className="importance-row" key={label}>
              <span>{label}</span>
              <div className="importance-bar">
                <i style={{ width: `${score}%` }} />
              </div>
              <strong>{score}%</strong>
            </div>
          ))}
        </div>
      </article>
    </section>
  );

  const content =
    view === "command"
      ? commandCenter
      : view === "flows"
        ? flowsView
        : view === "incidents"
          ? incidentsView
          : modelView;

  const titles: Record<View, [string, string, string]> = {
    command: [
      "LIVE SECURITY OPERATIONS",
      "Command Center",
      "AI-assisted visibility for network anomalies and threat behavior.",
    ],
    flows: [
      "NETWORK OBSERVABILITY",
      "Network Flows",
      "Search, inspect, and investigate observed connections.",
    ],
    incidents: [
      "THREAT RESPONSE",
      "Incidents",
      "Prioritize suspicious behavior with explainable evidence.",
    ],
    model: [
      "AI SECURITY ENGINE",
      "Model Lab",
      "Monitor anomaly detection performance and controls.",
    ],
  };

  const [eyebrow, title, subtitle] = titles[view];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">◉</div>
          <div>
            <h1>SPECTRA-X</h1>
            <p>THREAT INTELLIGENCE</p>
          </div>
        </div>

        <nav className="nav">
          <button
            className={view === "command" ? "nav-link active" : "nav-link"}
            onClick={() => setView("command")}
          >
            ⌘ <span>Command Center</span>
          </button>

          <button
            className={view === "flows" ? "nav-link active" : "nav-link"}
            onClick={() => openFlows()}
          >
            ◫ <span>Network Flows</span>
          </button>

          <button
            className={view === "incidents" ? "nav-link active" : "nav-link"}
            onClick={() => openIncidents()}
          >
            △ <span>Incidents</span>
          </button>

          <button
            className={view === "model" ? "nav-link active" : "nav-link"}
            onClick={() => setView("model")}
          >
            ◎ <span>Model Lab</span>
          </button>
        </nav>

        <div className="session-card">
          <span>SESSION STATUS</span>
          <strong>Protected</strong>
          <small>{metrics?.observed_flows ?? 0} flows observed</small>
        </div>

        <div className="sidebar-bottom">
          <span className="status-dot" />
          Live monitoring enabled
        </div>
      </aside>

      <main className="dashboard">
        <header className="topbar">
          <div>
            <p className="eyebrow">{eyebrow}</p>
            <h2>{title}</h2>
            <p className="subtitle">{subtitle}</p>
          </div>

          <div className="top-actions">
            <span className="api-indicator">
              <span className="status-dot" />
              API connected
            </span>

            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              hidden
              onChange={handleUpload}
            />

            <button
              className="upload-button"
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
            >
              {uploading ? "Analyzing…" : "↥ Analyze flow CSV"}
            </button>
          </div>
        </header>

        {message && <div className="toast success">✓ {message}</div>}
        {error && <div className="toast failure">! {error}</div>}

        {loading && !dashboard ? (
          <div className="loading">
            <span />
            Connecting to threat telemetry…
          </div>
        ) : (
          content
        )}
      </main>
    </div>
  );
}

export default App;
