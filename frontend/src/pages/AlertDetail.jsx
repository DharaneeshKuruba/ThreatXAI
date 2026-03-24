// pages/AlertDetail.jsx — Per-alert SHAP waterfall + LIME bar chart
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getAlertDetail, explainSHAP, explainLIME } from '../api/client';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, ReferenceLine
} from 'recharts';

const SAMPLE_ALERT = {
    alert_id: 'demo-alert-1',
    timestamp: new Date().toISOString(),
    src_ip: '10.0.0.1',
    dst_ip: '192.168.1.100',
    protocol: 'TCP',
    prediction: 1,
    label: 'Attack',
    confidence: 0.97,
    cluster_label: 'SYN Flood / DDoS Campaign',
    cluster_similarity: 0.94,
    shap: {
        top_features: [
            ['SYN Flag Count', 0.423],
            ['Flow Bytes/s', 0.381],
            ['Flow Packets/s', 0.291],
            ['Total Fwd Packets', 0.234],
            ['Init_Win_bytes_forward', -0.198],
            ['ACK Flag Count', -0.156],
            ['Flow Duration', 0.134],
            ['Fwd Packet Length Mean', 0.112],
            ['Total Backward Packets', -0.098],
            ['Flow IAT Mean', 0.087],
        ]
    },
    lime: [
        { feature: 'SYN Flag Count > 2.5', weight: 0.312 },
        { feature: 'Flow Bytes/s > 1e6', weight: 0.287 },
        { feature: 'Flow Packets/s > 1000', weight: 0.231 },
        { feature: 'Total Fwd Packets > 500', weight: 0.198 },
        { feature: 'Init_Win_bytes_forward <= 0', weight: -0.165 },
        { feature: 'ACK Flag Count <= 1', weight: -0.134 },
        { feature: 'Flow Duration <= 1e5', weight: 0.112 },
        { feature: 'Down/Up Ratio <= 0.1', weight: 0.089 },
    ]
};

function SHAPWaterfall({ features }) {
    if (!features || features.length === 0) return null;
    const maxAbs = Math.max(...features.map(f => Math.abs(f[1])));

    return (
        <div className="shap-bar-container">
            {features.map(([name, val], i) => {
                const pct = Math.abs(val) / maxAbs * 100;
                const isPos = val > 0;
                return (
                    <div key={i} className="shap-bar-row">
                        <div className="shap-feature-name" title={name}>{name}</div>
                        <div className="shap-bar-track">
                            <div
                                className={`shap-bar-fill ${isPos ? 'positive' : 'negative'}`}
                                style={{ width: `${pct}%`, ...(isPos ? { left: 0 } : { right: 0 }) }}
                            />
                        </div>
                        <div className="shap-value-text" style={{ color: isPos ? '#f87171' : '#67e8f9' }}>
                            {isPos ? '+' : ''}{val.toFixed(4)}
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

function LIMEChart({ features }) {
    if (!features || features.length === 0) return null;
    const data = features.map(f => ({
        name: f.feature || f[0],
        value: f.weight !== undefined ? f.weight : f[1],
    }));

    return (
        <ResponsiveContainer width="100%" height={280}>
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 20, top: 8, bottom: 8 }}>
                <XAxis type="number" tickFormatter={v => v.toFixed(2)} />
                <YAxis type="category" dataKey="name" width={200} tick={{ fontSize: 11, fill: 'var(--text-secondary)', fontFamily: 'JetBrains Mono' }} />
                <Tooltip
                    formatter={(v) => [v.toFixed(4), 'LIME Weight']}
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
                    labelStyle={{ color: 'var(--text-primary)' }}
                />
                <ReferenceLine x={0} stroke="rgba(255,255,255,0.1)" />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {data.map((d, i) => (
                        <Cell key={i} fill={d.value > 0 ? '#ef4444' : '#06b6d4'} fillOpacity={0.85} />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
}

export default function AlertDetail() {
    const { alertId } = useParams();
    const navigate = useNavigate();
    const [alert, setAlert] = useState(null);
    const [tab, setTab] = useState('shap');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        getAlertDetail(alertId)
            .then(setAlert)
            .catch(() => setAlert(SAMPLE_ALERT))
            .finally(() => setLoading(false));
    }, [alertId]);

    if (loading) return <div style={{ padding: 60, textAlign: 'center' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>;
    if (!alert) return <div className="empty-state"><div className="empty-state-icon">🔍</div><div className="empty-state-text">Alert not found</div></div>;

    // Map backend SHAP format to frontend format
    const shapFeatures = alert.shap?.top_features || [];
    // Map backend LIME format - empty array means no LIME data yet
    const limeFeatures = Array.isArray(alert.lime) && alert.lime.length > 0 
        ? alert.lime 
        : (shapFeatures.length > 0 
            ? shapFeatures.map(([feature, value]) => ({ feature, weight: value })) 
            : []);

    return (
        <>
            <div className="page-header">
                <div>
                    <button className="btn btn-ghost" style={{ marginBottom: 12 }} onClick={() => navigate(-1)}>
                        ← Back
                    </button>
                    <h1 className="page-title">
                        {alert.prediction === 1 ? '🚨' : '✅'} Alert Detail
                    </h1>
                    <p className="page-subtitle mono">{alert.alert_id}</p>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
                    <span className={`badge ${alert.prediction === 1 ? 'attack' : 'benign'}`} style={{ fontSize: 16, padding: '8px 16px' }}>
                        {alert.label}
                    </span>
                    <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                        Confidence: <strong style={{ color: alert.confidence > 0.8 ? 'var(--danger)' : 'var(--success)' }}>
                            {Math.round(alert.confidence * 100)}%
                        </strong>
                    </span>
                </div>
            </div>

            <div className="page-content">
                {/* Alert metadata */}
                <div className="grid-3" style={{ marginBottom: 20 }}>
                    {[
                        { label: 'Source IP', value: alert.src_ip || '—', color: 'var(--info)' },
                        { label: 'Destination IP', value: alert.dst_ip || '—', color: 'var(--text-primary)' },
                        { label: 'Protocol', value: alert.protocol || '—', color: 'var(--warning)' },
                    ].map(item => (
                        <div key={item.label} className="card">
                            <div className="card-title">{item.label}</div>
                            <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: item.color }}>{item.value}</div>
                        </div>
                    ))}
                </div>

                {/* EDAC Campaign */}
                {alert.cluster_label && (
                    <div className="card" style={{
                        background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.08))',
                        border: '1px solid rgba(99,102,241,0.25)',
                        marginBottom: 20,
                        display: 'flex', alignItems: 'center', gap: 16
                    }}>
                        <div style={{ fontSize: 28 }}>🔗</div>
                        <div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>EDAC Campaign Assignment</div>
                            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--accent-light)', marginTop: 4 }}>{alert.cluster_label}</div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                                Similarity to centroid: <strong>{Math.round((alert.cluster_similarity || 0.94) * 100)}%</strong>
                            </div>
                        </div>
                    </div>
                )}

                {/* SHAP / LIME Tabs */}
                <div className="card">
                    <div className="tabs">
                        <button className={`tab ${tab === 'shap' ? 'active' : ''}`} onClick={() => setTab('shap')}>
                            🎯 SHAP Explanation
                        </button>
                        <button className={`tab ${tab === 'lime' ? 'active' : ''}`} onClick={() => setTab('lime')}>
                            🟦 LIME Explanation
                        </button>
                    </div>

                    {tab === 'shap' && (
                        <>
                            <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <strong style={{ color: 'var(--accent-light)' }}>SHAP (SHapley Additive Explanations)</strong> — Global method.
                                Red bars push the prediction towards <em>Attack</em>, blue bars push towards <em>Benign</em>.
                            </div>
                            <SHAPWaterfall features={shapFeatures} />
                        </>
                    )}

                    {tab === 'lime' && (
                        <>
                            <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <strong style={{ color: 'var(--info)' }}>LIME (Local Interpretable Model-Agnostic Explanations)</strong> — Local method.
                                Shows which feature conditions contributed to this specific prediction.
                            </div>
                            <LIMEChart features={limeFeatures} />
                        </>
                    )}
                </div>
            </div>
        </>
    );
}
