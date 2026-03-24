// pages/Clusters.jsx — Attack Campaign View (alerts grouped by SHAP similarity)
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getClusters, getClusterStats } from '../api/client';

const CLUSTER_ICONS = {
    'SYN Flood': '🌊',
    'DDoS': '🌊',
    'Port Scan': '🔍',
    'Brute Force': '🔨',
    'Slow': '🐌',
    'Botnet': '🤖',
    'Infiltration': '👤',
    'Heartbleed': '💔',
    'default': '⚠️',
};

function getIcon(label) {
    for (const [key, icon] of Object.entries(CLUSTER_ICONS)) {
        if (key !== 'default' && label.includes(key)) return icon;
    }
    return CLUSTER_ICONS.default;
}

export default function Clusters() {
    const [clusters, setClusters] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [selected, setSelected] = useState(null);
    const [isRealData, setIsRealData] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        const load = async () => {
            try {
                const [c, s] = await Promise.all([getClusters(), getClusterStats()]);
                setClusters(c.clusters || []);
                setStats(s);
                setIsRealData(true);
            } catch {
                setClusters([]);
                setStats(null);
                setIsRealData(false);
            } finally {
                setLoading(false);
            }
        };
        load();
    }, []);

    const displayStats = stats || { total_clusters: 0, total_alerts_clustered: 0 };

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">⚡ Attack Campaigns</h1>
                    <p className="page-subtitle">Alerts grouped by SHAP explanation similarity</p>
                </div>
            </div>

            <div className="page-content">
                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
                        <div className="spinner" />
                    </div>
                ) : clusters.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon">🔗</div>
                        <div className="empty-state-text">No campaigns identified</div>
                        <div className="empty-state-sub">
                            Attack campaigns will appear once malicious traffic is detected and clustered.
                        </div>
                    </div>
                ) : (
                    <>
                        {/* Stats row */}
                        <div className="grid-3" style={{ marginBottom: 24 }}>
                            <div className="stat-card accent">
                                <div className="stat-icon accent">🔗</div>
                                <div className="stat-value">{displayStats.total_clusters}</div>
                                <div className="stat-label">Distinct Campaigns</div>
                            </div>
                            <div className="stat-card danger">
                                <div className="stat-icon danger">🚨</div>
                                <div className="stat-value">{displayStats.total_alerts_clustered}</div>
                                <div className="stat-label">Alerts Clustered</div>
                            </div>
                            <div className="stat-card success">
                                <div className="stat-icon success">📉</div>
                                <div className="stat-value">
                                    {displayStats.total_alerts_clustered > 0
                                        ? `${Math.round((1 - displayStats.total_clusters / displayStats.total_alerts_clustered) * 100)}%`
                                        : '—'}
                                </div>
                                <div className="stat-label">Alert Reduction</div>
                            </div>
                        </div>

                        {/* Cluster Cards */}
                        <div className="clusters-grid">
                            {clusters.map((cluster) => (
                                <div
                                    key={cluster.cluster_id}
                                    className="cluster-card"
                                    onClick={() => setSelected(selected === cluster.cluster_id ? null : cluster.cluster_id)}
                                >
                                    <div className="cluster-header">
                                        <div>
                                            <div style={{ fontSize: 20, marginBottom: 6 }}>{getIcon(cluster.label)}</div>
                                            <div className="cluster-label">{cluster.label}</div>
                                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'monospace' }}>
                                                {cluster.cluster_id}
                                            </div>
                                        </div>
                                        <div style={{ textAlign: 'right' }}>
                                            <div className="cluster-count">{cluster.member_count}</div>
                                            <div className="cluster-count-label">alerts</div>
                                        </div>
                                    </div>

                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.8px' }}>
                                        Top SHAP Features (Centroid)
                                    </div>
                                    <div className="cluster-top-features">
                                        {cluster.top_shap_features.slice(0, 4).map((f, i) => (
                                            <div key={i} className="cluster-feature-row">
                                                <span className="cluster-feature-name">{f.feature}</span>
                                                <span className={`cluster-feature-val ${f.shap_value > 0 ? 'pos' : 'neg'}`}>
                                                    {f.shap_value > 0 ? '+' : ''}{f.shap_value.toFixed(3)}
                                                </span>
                                            </div>
                                        ))}
                                    </div>

                                    {selected === cluster.cluster_id && (
                                        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
                                                {cluster.alert_ids.length} sample alert IDs:
                                            </div>
                                            {cluster.alert_ids.slice(0, 5).map(id => (
                                                <div key={id} className="mono" style={{ fontSize: 10, color: 'var(--info)', cursor: 'pointer', padding: '2px 0' }}
                                                    onClick={e => { e.stopPropagation(); navigate(`/alerts/${id}`); }}>
                                                    → {id}
                                                </div>
                                            ))}
                                            <button
                                                className="btn btn-primary"
                                                style={{ marginTop: 12, width: '100%', justifyContent: 'center' }}
                                                onClick={e => { e.stopPropagation(); navigate(`/?cluster=${cluster.cluster_id}`); }}
                                            >
                                                View All {cluster.member_count} Alerts
                                            </button>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </>
                )}
            </div>
        </>
    );
}
