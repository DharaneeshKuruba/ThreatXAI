// pages/Dashboard.jsx — Live monitoring feed
import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getAlerts, getAlertStats } from '../api/client';

function ConfidenceBar({ value }) {
    const pct = Math.round(value * 100);
    return (
        <div className="confidence-bar">
            <div className="confidence-track">
                <div className="confidence-fill" style={{ width: `${pct}%` }} />
            </div>
            <span className="mono" style={{ color: value > 0.8 ? '#f87171' : '#86efac', minWidth: 36 }}>{pct}%</span>
        </div>
    );
}

export default function Dashboard({ capturing, setAlertCount, pollingInterval = 3 }) {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('all');
    const [isRealData, setIsRealData] = useState(false);
    const navigate = useNavigate();
    const [searchParams, setSearchParams] = useSearchParams();
    const clusterFilter = searchParams.get('cluster');

    const fetchAlerts = useCallback(async () => {
        try {
            const prediction = filter === 'attack' ? 1 : filter === 'benign' ? 0 : null;
            const data = await getAlerts(0, 100, prediction);
            setAlerts(data);
            setIsRealData(true);
            setAlertCount(data.filter(a => a.prediction === 1).length);
        } catch {
            setAlerts([]);
            setIsRealData(false);
            setAlertCount(0);
        } finally {
            setLoading(false);
        }
    }, [filter, setAlertCount]);

    const fetchStats = useCallback(async () => {
        try {
            const s = await getAlertStats();
            setStats(s);
        } catch {
            setStats(null);
        }
    }, []);

    useEffect(() => {
        fetchAlerts();
        fetchStats();
    }, [fetchAlerts, fetchStats]);

    useEffect(() => {
        if (!capturing) return;
        const intervalMs = Math.max(1, pollingInterval) * 1000;
        const interval = setInterval(() => {
            fetchAlerts();
            fetchStats();
        }, intervalMs);
        return () => clearInterval(interval);
    }, [capturing, fetchAlerts, fetchStats, pollingInterval]);

    const displayStats = stats || { total_alerts: 0, attacks: 0, benign: 0, unique_clusters: 0, attack_rate: 0 };

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">
                        {capturing && <span className="live-dot" style={{ marginRight: 10 }}></span>}
                        Live Network Monitor
                    </h1>
                    <p className="page-subtitle">
                        {capturing ? 'Real-time packet analysis active' : 'Packet capture idle'}
                    </p>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {isRealData && (
                        <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: 6,
                            padding: '4px 10px', borderRadius: 99, fontSize: 10, fontWeight: 600,
                            background: 'var(--success-bg)', color: 'var(--success)', border: '1px solid rgba(34,197,94,0.2)'
                        }}>
                            <span className="live-dot" style={{ width: 6, height: 6, background: 'var(--success)' }}></span>
                            Connected
                        </span>
                    )}
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {new Date().toLocaleTimeString()}
                    </span>
                </div>
            </div>

            <div className="page-content">
                {/* Stats */}
                <div className="stats-grid">
                    <div className="stat-card accent">
                        <div className="stat-icon accent">📡</div>
                        <div className="stat-value">{displayStats.total_alerts.toLocaleString()}</div>
                        <div className="stat-label">Total Flows Analyzed</div>
                    </div>
                    <div className="stat-card danger">
                        <div className="stat-icon danger">🚨</div>
                        <div className="stat-value" style={{ color: 'var(--danger)' }}>{displayStats.attacks.toLocaleString()}</div>
                        <div className="stat-label">Attacks Detected</div>
                    </div>
                    <div className="stat-card success">
                        <div className="stat-icon success">✅</div>
                        <div className="stat-value" style={{ color: 'var(--success)' }}>{displayStats.benign.toLocaleString()}</div>
                        <div className="stat-label">Benign Traffic</div>
                    </div>
                    <div className="stat-card warning">
                        <div className="stat-icon warning">🔗</div>
                        <div className="stat-value" style={{ color: 'var(--warning)' }}>{displayStats.unique_clusters}</div>
                        <div className="stat-label">Attack Campaigns</div>
                    </div>
                </div>

                {/* Alert Table */}
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div className="card-title" style={{ margin: 0 }}>
                            🚨 Alert Feed
                            {capturing && <span className="badge" style={{ background: 'var(--success-bg)', color: 'var(--success)', fontSize: 10, marginLeft: 8 }}>● LIVE</span>}
                            {clusterFilter && <span className="badge" style={{ background: 'rgba(139,92,246,0.15)', color: '#a78bfa', fontSize: 10, marginLeft: 8 }}>Campaign Filter</span>}
                        </div>
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {['all', 'attack', 'benign'].map(f => (
                                <button key={f} className={`tab ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                                    {f.charAt(0).toUpperCase() + f.slice(1)}
                                </button>
                            ))}
                        </div>
                    </div>

                    {clusterFilter && (
                        <div style={{ padding: '10px 20px', background: 'rgba(139,92,246,0.08)', borderBottom: '1px solid rgba(139,92,246,0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: 12, color: '#a78bfa' }}>
                                🔗 Showing alerts from campaign: <strong>{clusterFilter}</strong>
                            </span>
                            <button className="btn" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => setSearchParams({})}>
                                ✕ Clear Filter
                            </button>
                        </div>
                    )}

                    {loading ? (
                        <div style={{ padding: 40, textAlign: 'center' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
                    ) : alerts.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon">{isRealData ? '📭' : '🔌'}</div>
                            <div className="empty-state-text">
                                {isRealData ? 'No alerts recorded' : 'Waiting for connection'}
                            </div>
                            <div className="empty-state-sub">
                                {isRealData
                                    ? 'Start packet capture to begin analyzing live traffic.'
                                    : 'Ensure the backend service is running.'}
                            </div>
                        </div>
                    ) : (
                        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                            <table className="alerts-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Source IP</th>
                                        <th>Destination IP</th>
                                        <th>Proto</th>
                                        <th>Status</th>
                                        <th>Confidence</th>
                                        <th>Campaign</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {alerts
                                        .filter(a => filter === 'all' || (filter === 'attack' ? a.prediction === 1 : a.prediction === 0))
                                        .filter(a => !clusterFilter || a.cluster_id === clusterFilter)
                                        .slice(0, 50).map(alert => (
                                        <tr key={alert.alert_id} onClick={() => navigate(`/alerts/${alert.alert_id}`)}>
                                            <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                                                {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'}
                                            </td>
                                            <td className="mono" style={{ color: 'var(--info)' }}>{alert.src_ip || '—'}</td>
                                            <td className="mono" style={{ color: 'var(--text-secondary)' }}>{alert.dst_ip || '—'}</td>
                                            <td><span className="mono" style={{ fontSize: 11 }}>{alert.protocol || 'TCP'}</span></td>
                                            <td>
                                                <span className={`badge ${alert.prediction === 1 ? 'attack' : 'benign'}`}>
                                                    {alert.prediction === 1 ? '⚠ Attack' : '✓ Benign'}
                                                </span>
                                            </td>
                                            <td style={{ minWidth: 140 }}><ConfidenceBar value={alert.confidence} /></td>
                                            <td>
                                                {alert.cluster_label ? (
                                                    <span className="badge cluster" style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                        🔗 {alert.cluster_label}
                                                    </span>
                                                ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                                            </td>
                                            <td>
                                                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11 }}
                                                    onClick={e => { e.stopPropagation(); navigate(`/alerts/${alert.alert_id}`); }}>
                                                    Explain →
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
