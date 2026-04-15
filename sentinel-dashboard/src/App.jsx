import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  Shield, AlertTriangle, CheckCircle2, Activity, Zap,
  Clock, ChevronRight, RefreshCw, Server, Lock, Database,
  XCircle, BarChart3, Radio, Sparkles, Code, ChevronDown,
  ChevronUp, Copy, Check
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, CartesianGrid, Area, AreaChart
} from 'recharts'

const API = 'http://localhost:8001'

const SEVERITY_COLORS = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e'
}
const SEVERITY_BG = {
  critical: 'bg-red-500/10 border-red-500/30 text-red-400',
  high: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  medium: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  low: 'bg-green-500/10 border-green-500/30 text-green-400',
}
const STATUS_BADGE = {
  open: 'bg-red-500/20 text-red-400',
  acknowledged: 'bg-yellow-500/20 text-yellow-400',
  resolved: 'bg-cyan-500/20 text-cyan-400',
}
const DETECTION_ICONS = {
  brute_force: Lock, credential_stuffing: Lock, rate_abuse: Zap,
  data_exfiltration: Database, multivariate_anomaly: Activity,
  schema_drift: Database, privilege_escalation: AlertTriangle,
  release_regression: Server, metric_anomaly: BarChart3,
  ingestion_anomaly: Database, sql_injection_probe: Shield,
}

function useApi(url, interval = 5000) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const refresh = useCallback(() => {
    fetch(`${API}${url}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [url])
  useEffect(() => {
    refresh()
    const id = setInterval(refresh, interval)
    return () => clearInterval(id)
  }, [refresh, interval])
  return { data, loading, refresh }
}

// ── Stat Card ──────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, color = 'text-blue-400', pulse, aiGlow }) {
  return (
    <div className={`bg-[#111827] border rounded-xl p-5 transition-all
      ${pulse ? 'pulse-critical border-[#1e293b]' : ''}
      ${aiGlow ? 'border-purple-500/40 shadow-lg shadow-purple-900/20' : 'border-[#1e293b]'}
    `}>
      <div className="flex items-center justify-between mb-3">
        <div className={`p-2 rounded-lg ${aiGlow ? 'bg-purple-500/10' : 'bg-[#1e293b]'}`}>
          <Icon size={18} className={color} />
        </div>
        {sub && <span className="text-xs text-gray-500">{sub}</span>}
      </div>
      <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
      {aiGlow && (
        <div className="mt-2 flex items-center gap-1">
          <Sparkles size={9} className="text-purple-400" />
          <span className="text-[9px] text-purple-400 font-medium">AI-powered</span>
        </div>
      )}
    </div>
  )
}

// ── Alert Row ──────────────────────────────────────────────────────────────────
function AlertRow({ alert, onClick, aiActionTypes }) {
  const Icon = DETECTION_ICONS[alert.alert_type] || AlertTriangle
  const sevClass = SEVERITY_BG[alert.severity] || SEVERITY_BG.medium
  const statusClass = STATUS_BADGE[alert.status] || STATUS_BADGE.open
  const age = alert.created_at ? timeAgo(alert.created_at) : ''
  const isAiResolved = alert.resolution && aiActionTypes.has(alert.resolution.action_type)

  return (
    <div onClick={() => onClick(alert)}
      className="flex items-center gap-4 px-4 py-3 border-b border-[#1e293b] hover:bg-[#1e293b]/50 cursor-pointer transition-colors animate-slide-in">
      <div className={`p-2 rounded-lg border ${sevClass}`}><Icon size={16} /></div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <div className="text-sm font-medium text-gray-200 truncate">{alert.title}</div>
          {isAiResolved && (
            <span className="shrink-0 flex items-center gap-1 text-[9px] bg-purple-500/15 text-purple-400 border border-purple-500/25 px-1.5 py-0.5 rounded-full font-semibold">
              <Sparkles size={8} /> AI
            </span>
          )}
        </div>
        <div className="text-xs text-gray-500 mt-0.5 flex items-center gap-2">
          <span className="font-mono">{alert.detection_method}</span>
          <span>·</span>
          <span>{alert.alert_type}</span>
        </div>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <span className="font-mono text-xs text-gray-400">{alert.risk_score?.toFixed(0)}</span>
        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${statusClass}`}>{alert.status}</span>
        <span className="text-[10px] text-gray-600 w-16 text-right">{age}</span>
        <ChevronRight size={14} className="text-gray-600" />
      </div>
    </div>
  )
}

// ── Alert Detail Panel ─────────────────────────────────────────────────────────
function AlertDetail({ alert, onClose, aiActionTypes }) {
  const { data: detail } = useApi(`/api/v1/alerts/${alert.id}`, 10000)
  const a = detail || alert
  const sevClass = SEVERITY_BG[a.severity] || SEVERITY_BG.medium

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-lg bg-[#111827] border-l border-[#1e293b] h-full overflow-y-auto"
        onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <div className={`px-3 py-1 rounded-full border text-xs font-semibold uppercase ${sevClass}`}>{a.severity}</div>
            <button onClick={onClose} className="text-gray-500 hover:text-gray-300"><XCircle size={20} /></button>
          </div>
          <h2 className="text-lg font-semibold text-gray-100 mb-2">{a.title}</h2>
          <p className="text-sm text-gray-400 leading-relaxed mb-6">{a.description}</p>

          <div className="grid grid-cols-2 gap-4 mb-6">
            <InfoBlock label="Risk Score" value={`${a.risk_score?.toFixed(1)} / 100`} />
            <InfoBlock label="Detection" value={a.detection_method} />
            <InfoBlock label="Status" value={a.status} />
            <InfoBlock label="Alert Type" value={a.alert_type} />
          </div>

          {a.affected_resource && (
            <div className="mb-6">
              <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Affected Resource</div>
              <div className="bg-[#0a0e1a] border border-[#1e293b] rounded-lg p-3 font-mono text-xs text-gray-300">
                {JSON.stringify(a.affected_resource, null, 2)}
              </div>
            </div>
          )}

          {a.resolutions && a.resolutions.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Auto-Resolution Chain</div>
              {a.resolutions.map((r, i) => {
                const isAi = aiActionTypes.has(r.action_type)
                return (
                  <div key={i} className={`border rounded-lg p-4 mb-2 ${isAi ? 'bg-purple-500/5 border-purple-500/30' : 'bg-cyan-500/5 border-cyan-500/20'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle2 size={14} className={isAi ? 'text-purple-400' : 'text-cyan-400'} />
                      <span className={`text-sm font-medium ${isAi ? 'text-purple-300' : 'text-cyan-300'}`}>{r.action_type}</span>
                      {isAi && (
                        <span className="flex items-center gap-1 text-[9px] bg-purple-500/20 text-purple-400 border border-purple-500/30 px-1.5 py-0.5 rounded-full font-semibold">
                          <Sparkles size={8} /> AI-Generated
                        </span>
                      )}
                      <span className={`ml-auto text-[10px] px-2 py-0.5 rounded ${r.status === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>{r.status}</span>
                    </div>
                    <div className="text-xs text-gray-400">{r.details?.action || JSON.stringify(r.details)}</div>
                    {r.rollback_available && (
                      <div className="mt-2 text-[10px] text-yellow-500 flex items-center gap-1">
                        <RefreshCw size={10} /> Rollback available
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function InfoBlock({ label, value }) {
  return (
    <div className="bg-[#0a0e1a] border border-[#1e293b] rounded-lg p-3">
      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</div>
      <div className="text-sm font-mono text-gray-200 mt-1">{value}</div>
    </div>
  )
}

// ── AI Toast Notification ──────────────────────────────────────────────────────
function AiToast({ resolver, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 6000)
    return () => clearTimeout(t)
  }, [onDismiss])

  const className = resolver.action_type
    .split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('') + 'Resolver'

  return (
    <div className="fixed top-4 right-4 z-[60] w-80 bg-[#140f2a] border border-purple-500/50 rounded-xl p-4 shadow-2xl shadow-purple-900/40 animate-slide-in">
      <div className="flex items-start gap-3">
        <div className="bg-purple-500/20 border border-purple-500/30 p-2 rounded-lg shrink-0">
          <Sparkles size={16} className="text-purple-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold text-purple-300 mb-1">AI Resolver Synthesised</div>
          <div className="text-xs text-gray-400 leading-relaxed">
            Claude generated{' '}
            <span className="font-mono text-purple-300">{className}</span>
            {' '}to handle{' '}
            <span className="text-gray-200">{resolver.threat_type}</span> threats
          </div>
          <div className="mt-2 flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[10px] text-green-400">Registered & executing now</span>
          </div>
        </div>
        <button onClick={onDismiss} className="text-gray-600 hover:text-gray-400 shrink-0">
          <XCircle size={14} />
        </button>
      </div>
    </div>
  )
}

// ── Generated Resolver Card ────────────────────────────────────────────────────
function ResolverCard({ resolver }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(resolver.code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const className = resolver.action_type
    .split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('') + 'Resolver'

  return (
    <div className="bg-[#0a0e1a] border border-purple-500/20 rounded-xl overflow-hidden hover:border-purple-500/40 transition-colors">
      <div className="px-5 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="bg-purple-500/10 border border-purple-500/30 p-2 rounded-lg">
              <Sparkles size={16} className="text-purple-400" />
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-200 font-mono">{className}</div>
              <div className="text-xs text-gray-500 mt-0.5">
                Threat type: <span className="text-purple-400 font-mono">{resolver.threat_type}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] bg-green-500/20 text-green-400 border border-green-500/20 px-2 py-0.5 rounded font-semibold uppercase">
              {resolver.status}
            </span>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded font-mono">
            action: {resolver.action_type}
          </span>
          <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded flex items-center gap-1">
            <Sparkles size={8} /> claude-sonnet-4-6
          </span>
          <span className="text-[10px] text-gray-600 font-mono ml-auto">
            {resolver.generated_at ? timeAgo(resolver.generated_at) : ''}
          </span>
        </div>
      </div>

      <div className="px-5 pb-4 border-t border-[#1e293b]">
        <button onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 transition-colors pt-3">
          <Code size={12} />
          {expanded ? 'Hide' : 'View'} generated source
          {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>

        {expanded && (
          <div className="mt-3">
            <div className="flex items-center justify-between bg-[#111827] border border-[#1e293b] rounded-t-lg px-4 py-2">
              <span className="text-[10px] text-gray-600 font-mono">python — AI-generated</span>
              <button onClick={copy}
                className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-200 transition-colors">
                {copied ? <Check size={10} className="text-green-400" /> : <Copy size={10} />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="bg-[#0d1117] border border-t-0 border-[#1e293b] rounded-b-lg p-4 overflow-x-auto overflow-y-auto text-[11px] leading-relaxed font-mono text-gray-300 max-h-96 whitespace-pre">
              {resolver.code}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function App() {
  const { data: stats } = useApi('/api/v1/stats', 4000)
  const { data: alertsData } = useApi('/api/v1/alerts?limit=50', 3000)
  const { data: liveData } = useApi('/api/v1/live/alerts', 2000)
  const { data: engineStatus } = useApi('/api/v1/engine/status', 8000)
  const { data: generatedData } = useApi('/api/v1/generated-resolvers', 3000)

  const [selectedAlert, setSelectedAlert] = useState(null)
  const [page, setPage] = useState('dashboard')
  const [aiToast, setAiToast] = useState(null)

  const prevResolverCount = useRef(0)

  // Fire toast when a new resolver appears
  useEffect(() => {
    const items = generatedData?.items || []
    if (items.length > prevResolverCount.current && prevResolverCount.current > 0) {
      setAiToast(items[0])
    }
    prevResolverCount.current = items.length
  }, [generatedData])

  const generatedResolvers = generatedData?.items || []
  const aiActionTypes = new Set(generatedResolvers.map(r => r.action_type))

  const alerts = alertsData?.items || []
  const s = stats || {}

  const sevDist = s.severity_distribution || {}
  const pieData = Object.entries(sevDist).map(([k, v]) => ({ name: k, value: v }))

  const typeDist = s.alert_type_distribution || {}
  const barData = Object.entries(typeDist).map(([k, v]) => ({ name: k.replace(/_/g, ' '), count: v }))

  const timeline = alerts.slice(0, 20).reverse().map((a, i) => ({
    time: i, risk: a.risk_score || 0
  }))

  const NAV_PAGES = ['dashboard', 'alerts', 'engine', 'ai']

  return (
    <div className="min-h-screen bg-[#0a0e1a]">
      {/* ── Header ── */}
      <header className="border-b border-[#1e293b] bg-[#111827]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-[1600px] mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-blue-500/10 border border-blue-500/30 p-1.5 rounded-lg">
              <Shield size={20} className="text-blue-400" />
            </div>
            <span className="font-semibold text-gray-100 tracking-tight">SentinelShield</span>
            <span className="text-[10px] bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full font-mono">v2.0</span>
          </div>
          <nav className="flex items-center gap-1">
            {NAV_PAGES.map(p => (
              <button key={p} onClick={() => setPage(p)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5
                  ${page === p
                    ? p === 'ai' ? 'bg-purple-500/10 text-purple-400' : 'bg-blue-500/10 text-blue-400'
                    : 'text-gray-500 hover:text-gray-300'
                  }`}>
                {p === 'ai' && <Sparkles size={11} />}
                {p === 'ai' ? 'AI Resolvers' : p.charAt(0).toUpperCase() + p.slice(1)}
                {p === 'ai' && generatedResolvers.length > 0 && (
                  <span className="bg-purple-500/20 text-purple-400 text-[9px] px-1.5 py-0.5 rounded-full font-mono">
                    {generatedResolvers.length}
                  </span>
                )}
              </button>
            ))}
          </nav>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5">
              <Radio size={10} className={`${liveData ? 'text-green-400 animate-pulse' : 'text-gray-600'}`} />
              <span className="text-[10px] text-gray-500">LIVE</span>
            </div>
            <span className="text-[10px] text-gray-600 font-mono">Monitoring NexusCloud Commerce</span>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto px-6 py-6">

        {/* ══════════════════════ DASHBOARD PAGE ══════════════════════ */}
        {page === 'dashboard' && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
              <StatCard icon={AlertTriangle} label="Total Alerts" value={s.total_alerts || 0} color="text-gray-200" />
              <StatCard icon={XCircle} label="Open Threats" value={s.open_alerts || 0} color="text-red-400" pulse={s.open_alerts > 0} />
              <StatCard icon={CheckCircle2} label="Resolved" value={s.resolved_alerts || 0} color="text-cyan-400" />
              <StatCard icon={Zap} label="Critical" value={s.critical_count || 0} color="text-red-500" />
              <StatCard icon={Activity} label="Events Ingested" value={s.total_events || 0} color="text-blue-400" />
              <StatCard icon={Shield} label="Auto-Resolve Rate" value={`${s.auto_resolution_rate || 0}%`} color="text-green-400" />
              <StatCard
                icon={Sparkles}
                label="AI Resolvers"
                value={generatedResolvers.length}
                color="text-purple-400"
                aiGlow={generatedResolvers.length > 0}
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
              <div className="lg:col-span-2 bg-[#111827] border border-[#1e293b] rounded-xl p-5">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">Risk Score Timeline</div>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeline}>
                    <defs>
                      <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#64748b' }} />
                    <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="risk" stroke="#ef4444" fill="url(#riskGrad)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-[#111827] border border-[#1e293b] rounded-xl p-5">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">Severity Distribution</div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                      outerRadius={70} innerRadius={40} paddingAngle={4}>
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={SEVERITY_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap gap-3 justify-center mt-2">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5 text-[10px]">
                      <div className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[d.name] }} />
                      <span className="text-gray-400">{d.name}: {d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {barData.length > 0 && (
              <div className="bg-[#111827] border border-[#1e293b] rounded-xl p-5 mb-6">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">Alerts by Threat Type</div>
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={barData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#64748b' }} angle={-20} textAnchor="end" height={50} />
                    <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                    <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* AI Resolver spotlight banner (only when at least one exists) */}
            {generatedResolvers.length > 0 && (
              <div className="bg-gradient-to-r from-purple-900/20 to-[#111827] border border-purple-500/30 rounded-xl p-4 mb-6 flex items-center gap-4">
                <div className="bg-purple-500/20 border border-purple-500/30 p-3 rounded-xl shrink-0">
                  <Sparkles size={20} className="text-purple-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-semibold text-purple-300">
                    {generatedResolvers.length} AI-Synthesised Resolver{generatedResolvers.length > 1 ? 's' : ''} Active
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5">
                    Claude automatically wrote new resolver code for unknown threat types detected in this session.
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {generatedResolvers.map(r => (
                      <span key={r.id} className="text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded">
                        {r.action_type}
                      </span>
                    ))}
                  </div>
                </div>
                <button onClick={() => setPage('ai')}
                  className="shrink-0 text-xs text-purple-400 hover:text-purple-300 border border-purple-500/30 hover:border-purple-500/60 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5">
                  View code <ChevronRight size={12} />
                </button>
              </div>
            )}

            <div className="bg-[#111827] border border-[#1e293b] rounded-xl overflow-hidden">
              <div className="px-5 py-4 border-b border-[#1e293b] flex items-center justify-between">
                <div className="text-xs text-gray-500 uppercase tracking-wider">Live Threat Feed</div>
                <div className="flex items-center gap-1.5">
                  <Radio size={8} className="text-green-400 animate-pulse" />
                  <span className="text-[10px] text-gray-600">Auto-refreshing</span>
                </div>
              </div>
              <div className="max-h-[400px] overflow-y-auto">
                {alerts.length === 0 ? (
                  <div className="p-8 text-center text-gray-600 text-sm">
                    No alerts yet. Run the demo simulator to generate threat scenarios.
                  </div>
                ) : (
                  alerts.map(a => (
                    <AlertRow key={a.id} alert={a} onClick={setSelectedAlert} aiActionTypes={aiActionTypes} />
                  ))
                )}
              </div>
            </div>
          </>
        )}

        {/* ══════════════════════ ALERTS PAGE ══════════════════════ */}
        {page === 'alerts' && (
          <div className="bg-[#111827] border border-[#1e293b] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e293b]">
              <div className="text-sm font-medium text-gray-200">All Alerts ({alertsData?.total || 0})</div>
            </div>
            <div className="max-h-[700px] overflow-y-auto">
              {alerts.map(a => (
                <AlertRow key={a.id} alert={a} onClick={setSelectedAlert} aiActionTypes={aiActionTypes} />
              ))}
            </div>
          </div>
        )}

        {/* ══════════════════════ ENGINE PAGE ══════════════════════ */}
        {page === 'engine' && (
          <div className="space-y-4">
            <div className="bg-[#111827] border border-[#1e293b] rounded-xl p-5">
              <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">Engine Status</div>
              {engineStatus ? (
                <div className="space-y-4">
                  <div className="bg-[#0a0e1a] border border-[#1e293b] rounded-lg p-4">
                    <div className="text-xs text-gray-500 mb-2">Collector</div>
                    <div className="grid grid-cols-3 gap-4 font-mono text-sm">
                      <div><span className="text-gray-500">Stream:</span> <span className="text-gray-200">{engineStatus.collector?.stream}</span></div>
                      <div><span className="text-gray-500">Processed:</span> <span className="text-blue-400">{engineStatus.collector?.events_processed}</span></div>
                      <div><span className="text-gray-500">Status:</span> <span className={engineStatus.collector?.running ? 'text-green-400' : 'text-red-400'}>{engineStatus.collector?.running ? 'RUNNING' : 'STOPPED'}</span></div>
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 mb-2">Detectors</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {engineStatus.detectors?.map((d, i) => (
                      <div key={i} className={`border rounded-lg p-4 ${d.name === 'SqlInjectionDetector' ? 'bg-purple-900/10 border-purple-500/20' : 'bg-[#0a0e1a] border-[#1e293b]'}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <div className="text-sm font-medium text-gray-200">{d.name}</div>
                          {d.name === 'SqlInjectionDetector' && (
                            <span className="text-[9px] bg-purple-500/15 text-purple-400 border border-purple-500/20 px-1.5 py-0.5 rounded-full flex items-center gap-1">
                              <Sparkles size={8} /> AI
                            </span>
                          )}
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-gray-500">Events analyzed</span>
                          <span className="font-mono text-blue-400">{d.events_analyzed}</span>
                        </div>
                        <div className="flex justify-between text-xs mt-1">
                          <span className="text-gray-500">Detections</span>
                          <span className="font-mono text-red-400">{d.detections}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-gray-600 text-sm">Loading engine status...</div>
              )}
            </div>

            {generatedResolvers.length > 0 && (
              <div className="bg-[#111827] border border-purple-500/20 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Sparkles size={14} className="text-purple-400" />
                    <div className="text-xs text-purple-400 uppercase tracking-wider">AI-Generated Resolvers in RESOLVER_MAP</div>
                  </div>
                  <span className="text-xs font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded">
                    {generatedResolvers.length} active
                  </span>
                </div>
                <div className="space-y-2">
                  {generatedResolvers.map(r => (
                    <div key={r.id} className="flex items-center justify-between bg-[#0a0e1a] border border-purple-500/10 rounded-lg px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                        <span className="text-sm font-mono text-gray-200">
                          {r.action_type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('') + 'Resolver'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span className="font-mono text-purple-400">{r.action_type}</span>
                        <span>·</span>
                        <span>{timeAgo(r.generated_at)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══════════════════════ AI RESOLVERS PAGE ══════════════════════ */}
        {page === 'ai' && (
          <div className="space-y-6">
            {/* Header banner */}
            <div className="bg-gradient-to-r from-purple-900/30 via-[#111827] to-[#111827] border border-purple-500/30 rounded-xl p-6">
              <div className="flex items-center gap-4">
                <div className="bg-purple-500/20 border border-purple-500/30 p-3 rounded-xl">
                  <Sparkles size={24} className="text-purple-400" />
                </div>
                <div>
                  <h1 className="text-lg font-semibold text-gray-100">AI Resolver Generator</h1>
                  <p className="text-sm text-gray-400 mt-1">
                    When SentinelShield detects a threat with no built-in resolver, Claude automatically
                    synthesises a new <span className="font-mono text-purple-400">BaseResolver</span> subclass,
                    registers it live, and executes it immediately.
                  </p>
                </div>
                <div className="ml-auto text-right shrink-0">
                  <div className="text-3xl font-bold font-mono text-purple-400">{generatedResolvers.length}</div>
                  <div className="text-xs text-gray-500 mt-1">resolver{generatedResolvers.length !== 1 ? 's' : ''} synthesised</div>
                </div>
              </div>

              <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-3">
                {[
                  { label: 'Trigger', value: 'Unknown resolver_action detected', icon: AlertTriangle, color: 'text-yellow-400' },
                  { label: 'Model', value: 'claude-sonnet-4-6', icon: Sparkles, color: 'text-purple-400' },
                  { label: 'Execution', value: 'exec() in sandboxed namespace', icon: Shield, color: 'text-green-400' },
                ].map(({ label, value, icon: Icon, color }) => (
                  <div key={label} className="bg-[#0a0e1a]/60 border border-[#1e293b] rounded-lg px-4 py-3 flex items-center gap-3">
                    <Icon size={14} className={color} />
                    <div>
                      <div className="text-[10px] text-gray-500 uppercase">{label}</div>
                      <div className={`text-xs font-mono mt-0.5 ${color}`}>{value}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Resolver list */}
            {generatedResolvers.length === 0 ? (
              <div className="bg-[#111827] border border-[#1e293b] rounded-xl p-12 text-center">
                <div className="bg-purple-500/10 border border-purple-500/20 p-4 rounded-full w-fit mx-auto mb-4">
                  <Sparkles size={28} className="text-purple-400" />
                </div>
                <div className="text-gray-400 text-sm mb-2">No AI-generated resolvers yet</div>
                <div className="text-gray-600 text-xs max-w-sm mx-auto leading-relaxed">
                  Run the demo simulator and trigger Phase 9 (SQL injection probe). The engine will
                  call Claude to synthesise a <span className="font-mono text-gray-400">SqlInjectionBlockResolver</span> on-the-fly.
                </div>
                <div className="mt-4 bg-[#0a0e1a] border border-[#1e293b] rounded-lg px-4 py-3 text-left inline-block">
                  <div className="text-[10px] text-gray-500 mb-1">Run the demo:</div>
                  <div className="font-mono text-xs text-gray-300">
                    docker compose exec sentinel-engine python -m scripts.demo_simulator
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="text-xs text-gray-500 uppercase tracking-wider">
                  Generated Resolvers — stored in <span className="font-mono text-gray-400">generated_resolvers</span> table
                </div>
                {generatedResolvers.map(r => (
                  <ResolverCard key={r.id} resolver={r} />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {selectedAlert && (
        <AlertDetail alert={selectedAlert} onClose={() => setSelectedAlert(null)} aiActionTypes={aiActionTypes} />
      )}

      {aiToast && <AiToast resolver={aiToast} onDismiss={() => setAiToast(null)} />}
    </div>
  )
}

function timeAgo(isoStr) {
  const seconds = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}
