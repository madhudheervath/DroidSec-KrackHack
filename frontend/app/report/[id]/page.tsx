'use client'

import { useState, useEffect, useMemo } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Shield, ShieldAlert, ShieldCheck, AlertTriangle, Info,
    FileText, ArrowLeft, Download, Code, ChevronDown,
    Bug, Lock, Wifi, Eye, Smartphone, Database, Key, Layers,
    BarChart3, Activity, Target, Zap, Clock, Package, FileCode,
    CheckCircle, XCircle, AlertCircle, TrendingDown, Brain
} from 'lucide-react'
import {
    RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
    PieChart, Pie
} from 'recharts'
import NeonCard from '../../components/NeonCard'
import CyberBackground from '../../components/CyberBackground'
import { apiUrl } from '../../lib/api'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */
interface Finding {
    id: string
    name: string
    description: string
    severity: string
    confidence?: string
    confidence_score?: number
    evidence?: string
    location?: string
    owasp?: string
    remediation?: string
    context?: string
    count?: number
    sample_locations?: string[]
    source_type?: string
}

interface Breakdown { critical?: number; high?: number; medium?: number; info?: number }

interface OWASPCategory { name: string; count: number; max_severity: string; findings?: Finding[] }

interface SecurityScore { score: number; grade: string; risk_level: string; summary?: string }

interface Report {
    scan_id: string
    package?: string
    apk_filename?: string
    timestamp?: string
    total_findings?: number
    unique_findings?: number
    files_scanned?: number
    code_files_scanned?: number
    java_files_scanned?: number
    smali_files_scanned?: number
    config_files_scanned?: number
    analysis_mode?: string
    dex_file_count?: number
    decompile_errors?: string[]
    security_score?: SecurityScore
    severity_breakdown?: Breakdown
    owasp_breakdown?: Record<string, OWASPCategory>
    findings?: Finding[]
    metadata?: {
        package?: string
        min_sdk?: string
        target_sdk?: string
        permissions?: string[]
        exported_components?: string[]
        libraries?: string[]
        activities?: string[]
        services?: string[]
        receivers?: string[]
        providers?: string[]
    }
}

interface AIAnalysis {
    executive_summary?: string
    threat_model?: { attack_vectors?: string[]; threat_actors?: string[]; impact_assessment?: string }
    critical_chains?: { name: string; chain: string; risk: string; exploit_difficulty: string }[]
    ai_findings?: { name: string; severity: string; description: string; evidence: string; remediation: string }[]
    prioritized_fixes?: { priority: number; finding: string; reason: string; effort: string; code_fix: string }[]
    security_recommendations?: string[]
    compliance_notes?: string
    available?: boolean
    error?: string
    provider?: string
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
const SEV: Record<string, { color: string; bg: string; border: string; icon: React.ReactNode; order: number }> = {
    critical: { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/40',    icon: <XCircle size={14} />,        order: 0 },
    high:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/40', icon: <AlertTriangle size={14} />,   order: 1 },
    medium:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/40', icon: <AlertCircle size={14} />,     order: 2 },
    info:     { color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/40',   icon: <Info size={14} />,            order: 3 },
}

const OWASP_ICONS: Record<string, React.ReactNode> = {
    M1: <Key size={16} />, M2: <Package size={16} />, M3: <Lock size={16} />,
    M4: <FileCode size={16} />, M5: <Wifi size={16} />, M6: <Eye size={16} />,
    M7: <Layers size={16} />, M8: <Database size={16} />, M9: <Smartphone size={16} />,
    M10: <Shield size={16} />,
}

function gradeStyle(g: string) {
    const m: Record<string, { ring: string; text: string; glow: string }> = {
        A: { ring: 'border-emerald-400', text: 'text-emerald-400', glow: 'shadow-[0_0_40px_rgba(52,211,153,0.4)]' },
        B: { ring: 'border-cyan-400',    text: 'text-cyan-400',    glow: 'shadow-[0_0_40px_rgba(34,211,238,0.4)]' },
        C: { ring: 'border-yellow-400',  text: 'text-yellow-400',  glow: 'shadow-[0_0_40px_rgba(250,204,21,0.4)]' },
        D: { ring: 'border-orange-400',  text: 'text-orange-400',  glow: 'shadow-[0_0_40px_rgba(251,146,60,0.4)]' },
        F: { ring: 'border-red-500',     text: 'text-red-500',     glow: 'shadow-[0_0_40px_rgba(239,68,68,0.5)]' },
    }
    return m[g] || m.F
}

function scoreColor(s: number) {
    if (s >= 85) return '#34d399'
    if (s >= 70) return '#22d3ee'
    if (s >= 50) return '#facc15'
    if (s >= 35) return '#fb923c'
    return '#ef4444'
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */
function ScoreRing({ score, grade }: { score: number; grade: string }) {
    const st = gradeStyle(grade)
    const C = 2 * Math.PI * 54
    return (
        <div className={`relative w-36 h-36 rounded-full ${st.glow}`}>
            <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
                <motion.circle cx="60" cy="60" r="54" fill="none"
                    stroke={scoreColor(score)} strokeWidth="6" strokeLinecap="round"
                    strokeDasharray={C}
                    initial={{ strokeDashoffset: C }}
                    animate={{ strokeDashoffset: C - (score / 100) * C }}
                    transition={{ duration: 1.5, ease: 'easeOut' }}
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-4xl font-black ${st.text}`}>{grade}</span>
                <span className="text-sm text-gray-400 font-bold">{score}/100</span>
            </div>
        </div>
    )
}

function Stat({ label, value, icon, color = 'text-white' }: { label: string; value: string | number; icon: React.ReactNode; color?: string }) {
    return (
        <div className="glass-card p-4 flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-white/5 ${color}`}>{icon}</div>
            <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold">{label}</p>
                <p className={`text-lg font-black ${color}`}>{value}</p>
            </div>
        </div>
    )
}

function SevPill({ severity }: { severity: string }) {
    const c = SEV[severity] || SEV.info
    return (
        <span className={`inline-flex items-center gap-1 text-[10px] font-black uppercase px-2 py-0.5 rounded ${c.bg} ${c.color} ${c.border} border`}>
            {c.icon} {severity}
        </span>
    )
}

function FindingCard({ finding, open = false }: { finding: Finding; open?: boolean }) {
    const [exp, setExp] = useState(open)
    const c = SEV[finding.severity] || SEV.info

    return (
        <motion.div layout className={`glass-card overflow-hidden border ${c.border}`}
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <button onClick={() => setExp(!exp)}
                className="w-full text-left p-5 flex items-start gap-4 hover:bg-white/[0.02] transition-colors">
                <div className={`mt-0.5 p-1.5 rounded ${c.bg} ${c.color}`}>{c.icon}</div>
                <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1.5">
                        <SevPill severity={finding.severity} />
                        <span className="text-[10px] font-bold text-gray-500 bg-white/5 px-1.5 py-0.5 rounded">{finding.id}</span>
                        {finding.owasp && <span className="text-[10px] font-bold text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/30">OWASP {finding.owasp}</span>}
                        {(finding.count ?? 0) > 1 && <span className="text-[10px] font-bold text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded">{finding.count} instances</span>}
                    </div>
                    <h3 className="text-sm font-bold text-white leading-tight">{finding.name}</h3>
                    <p className="text-xs text-gray-500 mt-1 truncate">{finding.location}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                    {finding.confidence_score != null && (
                        <div className="hidden sm:flex items-center gap-2">
                            <div className="w-12 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${Math.round(finding.confidence_score * 100)}%` }} />
                            </div>
                            <span className="text-[10px] text-gray-400 font-mono">{Math.round(finding.confidence_score * 100)}%</span>
                        </div>
                    )}
                    <ChevronDown size={16} className={`text-gray-500 transition-transform ${exp ? 'rotate-180' : ''}`} />
                </div>
            </button>

            <AnimatePresence>
                {exp && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                        <div className="px-5 pb-5 space-y-4 border-t border-white/5 pt-4">
                            <p className="text-xs text-gray-400 leading-relaxed">{finding.description}</p>

                            {finding.evidence && (
                                <div>
                                    <p className="text-[10px] font-black text-gray-500 mb-2 flex items-center gap-1.5 uppercase tracking-widest"><Code size={11} /> Evidence</p>
                                    <div className="bg-[#0d0d1a] rounded-lg border border-white/5 overflow-hidden">
                                        <div className="flex justify-between items-center px-3 py-1.5 bg-white/[0.02] border-b border-white/5">
                                            <span className="text-[9px] text-gray-600 truncate max-w-[70%]">{finding.location}</span>
                                            <span className="text-[9px] text-gray-700">{finding.source_type === 'smali_fallback' ? 'SMALI' : 'DECOMPILED'}</span>
                                        </div>
                                        <pre className="p-3 text-[11px] text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">{finding.evidence}</pre>
                                    </div>
                                </div>
                            )}

                            {finding.context && finding.context !== finding.evidence && (
                                <div>
                                    <p className="text-[10px] font-black text-gray-500 mb-2 uppercase tracking-widest">Source Context</p>
                                    <pre className="bg-[#0d0d1a] rounded-lg border border-white/5 p-3 text-[11px] text-gray-400 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">{finding.context}</pre>
                                </div>
                            )}

                            {finding.remediation && (
                                <div className="bg-emerald-500/[0.05] border border-emerald-500/20 rounded-lg p-4">
                                    <h4 className="text-emerald-400 text-[10px] font-black mb-2 flex items-center gap-1.5 uppercase tracking-widest"><CheckCircle size={12} /> Remediation</h4>
                                    <p className="text-xs text-gray-300 leading-relaxed">{finding.remediation}</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

/* ------------------------------------------------------------------ */
/*  Main Page                                                          */
/* ------------------------------------------------------------------ */
export default function ReportPage() {
    const params = useParams()
    const [report, setReport]       = useState<Report | null>(null)
    const [loading, setLoading]     = useState(true)
    const [filter, setFilter]       = useState('all')
    const [tab, setTab]             = useState<'findings' | 'owasp' | 'ai'>('findings')
    const [ai, setAi]               = useState<AIAnalysis | null>(null)
    const [aiLoading, setAiLoading] = useState(false)

    /* fetch report */
    useEffect(() => {
        if (!params.id) return
        ;(async () => {
            try {
                const r = await fetch(apiUrl(`/api/report/${params.id}`))
                if (!r.ok) throw new Error('not found')
                setReport(await r.json())
            } catch (e) { console.error(e) }
            finally { setLoading(false) }
        })()
    }, [params.id])

    /* lazy AI fetch */
    useEffect(() => {
        if (tab !== 'ai' || ai || aiLoading || !report) return
        ;(async () => {
            setAiLoading(true)
            try {
                const r = await fetch(apiUrl(`/api/ai/analyze/${params.id}`))
                setAi(r.ok ? await r.json() : { error: 'AI analysis unavailable', available: false })
            } catch { setAi({ error: 'Failed to reach AI endpoint', available: false }) }
            finally { setAiLoading(false) }
        })()
    }, [tab, ai, aiLoading, report, params.id])

    /* derived */
    const score      = report?.security_score?.score ?? 0
    const grade      = report?.security_score?.grade ?? '?'
    const bk         = report?.severity_breakdown ?? {}
    const findings   = report?.findings ?? []
    const meta       = report?.metadata ?? {}
    const total      = report?.total_findings ?? findings.length

    const filtered = useMemo(() =>
        findings
            .filter(f => filter === 'all' || f.severity === filter)
            .sort((a, b) => (SEV[a.severity]?.order ?? 3) - (SEV[b.severity]?.order ?? 3)),
        [findings, filter])

    const owaspData = useMemo(() => {
        if (!report?.owasp_breakdown) return []
        const mx = Math.max(10, ...Object.values(report.owasp_breakdown).map(c => c.count))
        return Object.entries(report.owasp_breakdown).map(([k, c]) => ({ subject: k, name: c.name, count: c.count, max_severity: c.max_severity, fullMark: mx }))
    }, [report])

    const sevChart = useMemo(() => [
        { name: 'Critical', value: bk.critical ?? 0, color: '#ef4444' },
        { name: 'High',     value: bk.high ?? 0,     color: '#f97316' },
        { name: 'Medium',   value: bk.medium ?? 0,   color: '#eab308' },
        { name: 'Info',     value: bk.info ?? 0,     color: '#3b82f6' },
    ].filter(d => d.value > 0), [bk])

    const ts = report?.timestamp ? new Date(report.timestamp).toLocaleString() : 'N/A'

    /* loading / error */
    if (loading) return (
        <div className="min-h-screen bg-[#0a0a12] flex items-center justify-center">
            <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}>
                <Shield size={48} className="text-green-400" />
            </motion.div>
        </div>
    )
    if (!report) return (
        <div className="min-h-screen bg-[#0a0a12] flex flex-col items-center justify-center text-red-500 font-mono gap-4">
            <ShieldAlert size={48} />
            <h1 className="text-2xl font-black">REPORT NOT FOUND</h1>
            <Link href="/" className="text-green-400 underline hover:text-green-300 text-sm">Return to Dashboard</Link>
        </div>
    )

    const gs = gradeStyle(grade)

    return (
        <div className="min-h-screen bg-[#0a0a12] text-white selection:bg-purple-500/30 pb-20">
            <CyberBackground />

            {/* NAV */}
            <nav className="border-b border-white/10 bg-black/60 backdrop-blur-xl sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
                    <Link href="/" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors text-sm">
                        <ArrowLeft size={18} /> Back
                    </Link>
                    <div className="flex items-center gap-3">
                        <span className="text-[10px] text-gray-600 font-mono hidden md:inline">ID: {report.scan_id}</span>
                        <a href={apiUrl(`/api/report/${params.id}/download`)}
                           className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded-lg transition-colors text-xs font-bold">
                            <Download size={14} /> Export
                        </a>
                    </div>
                </div>
            </nav>

            <main className="max-w-7xl mx-auto px-4 py-8 space-y-8">

                {/* ══════════ HERO ══════════ */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 md:p-8">
                    <div className="flex flex-col md:flex-row items-center gap-8">
                        <ScoreRing score={score} grade={grade} />

                        <div className="flex-1 text-center md:text-left space-y-3">
                            <div>
                                <h1 className="text-xl md:text-2xl font-black tracking-tight">{report.apk_filename || report.package || 'Unknown APK'}</h1>
                                <p className="text-sm text-gray-500 font-mono">{report.package}</p>
                            </div>
                            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl">{report.security_score?.summary}</p>
                            <div className="flex flex-wrap justify-center md:justify-start gap-3 pt-2">
                                <span className={`text-xs font-bold px-3 py-1 rounded-full border ${gs.ring} ${gs.text} bg-white/5`}>
                                    {report.security_score?.risk_level} Risk
                                </span>
                                <span className="text-xs text-gray-500 px-3 py-1 rounded-full border border-white/10 bg-white/5">
                                    <Clock size={10} className="inline mr-1 -mt-0.5" />{ts}
                                </span>
                                {report.analysis_mode && (
                                    <span className="text-xs text-gray-500 px-3 py-1 rounded-full border border-white/10 bg-white/5">
                                        {report.analysis_mode === 'full' ? '✓ Full Analysis' : `⚠ ${report.analysis_mode}`}
                                    </span>
                                )}
                            </div>
                        </div>

                        {/* donut */}
                        <div className="hidden lg:block w-36 h-36">
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie data={sevChart} dataKey="value" cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} strokeWidth={0}>
                                        {sevChart.map((d, i) => <Cell key={i} fill={d.color} />)}
                                    </Pie>
                                    <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #252540', borderRadius: 8, fontSize: 11 }} itemStyle={{ color: '#e4e4ef' }} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </motion.div>

                {/* ══════════ METRICS ROW ══════════ */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
                    className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    <Stat label="Total Findings" value={total}            icon={<Bug size={18} />}            color="text-white" />
                    <Stat label="Critical"       value={bk.critical ?? 0} icon={<XCircle size={18} />}        color="text-red-400" />
                    <Stat label="High"           value={bk.high ?? 0}     icon={<AlertTriangle size={18} />}  color="text-orange-400" />
                    <Stat label="Medium"         value={bk.medium ?? 0}   icon={<AlertCircle size={18} />}    color="text-yellow-400" />
                    <Stat label="Files Scanned"  value={report.files_scanned ?? 0} icon={<FileText size={18} />} color="text-cyan-400" />
                    <Stat label="Code Coverage"  value={`${report.java_files_scanned ?? 0}J / ${report.smali_files_scanned ?? 0}S`} icon={<FileCode size={18} />} color="text-purple-400" />
                </motion.div>

                {/* ══════════ ANALYSIS METRICS ══════════ */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="glass-card p-5">
                    <h2 className="text-sm font-black text-gray-300 mb-4 flex items-center gap-2">
                        <BarChart3 size={16} className="text-cyan-400" /> QUANTITATIVE ANALYSIS
                    </h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 text-center">
                        {[
                            { label: 'Java/Kotlin Files', value: report.java_files_scanned ?? 0,  color: '#22d3ee' },
                            { label: 'Smali Files',       value: report.smali_files_scanned ?? 0, color: '#a78bfa' },
                            { label: 'Config/XML',        value: report.config_files_scanned ?? 0,color: '#facc15' },
                            { label: 'DEX Files',         value: report.dex_file_count ?? 0,      color: '#f97316' },
                            { label: 'Permissions',       value: meta.permissions?.length ?? 0,    color: '#fb7185' },
                            { label: 'Components',        value: (meta.activities?.length ?? 0) + (meta.services?.length ?? 0) + (meta.receivers?.length ?? 0) + (meta.providers?.length ?? 0), color: '#34d399' },
                            { label: 'Libraries',         value: meta.libraries?.length ?? 0,      color: '#60a5fa' },
                        ].map(it => (
                            <div key={it.label} className="space-y-1">
                                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold">{it.label}</p>
                                <p className="text-2xl font-black" style={{ color: it.color }}>{it.value}</p>
                            </div>
                        ))}
                    </div>
                    <div className="flex flex-wrap gap-4 mt-4 pt-4 border-t border-white/5">
                        {meta.min_sdk && <span className="text-[10px] text-gray-500">Min SDK: <span className="text-gray-300 font-bold">{meta.min_sdk}</span></span>}
                        {meta.target_sdk && <span className="text-[10px] text-gray-500">Target SDK: <span className="text-gray-300 font-bold">{meta.target_sdk}</span></span>}
                        {(report.decompile_errors?.length ?? 0) > 0 && (
                            <span className="text-[10px] text-orange-400">⚠ {report.decompile_errors!.length} decompiler warning(s)</span>
                        )}
                    </div>
                </motion.div>

                {/* ══════════ TABS ══════════ */}
                <div className="flex gap-1 bg-white/5 rounded-lg p-1 w-fit">
                    {([
                        { k: 'findings' as const, l: 'Findings', ic: <Bug size={14} />, n: total },
                        { k: 'owasp'    as const, l: 'OWASP Top 10', ic: <Target size={14} /> },
                        { k: 'ai'       as const, l: 'AI Analysis', ic: <Brain size={14} /> },
                    ]).map(t => (
                        <button key={t.k} onClick={() => setTab(t.k)}
                            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-bold transition-all ${tab === t.k ? 'bg-white/10 text-white shadow-lg' : 'text-gray-500 hover:text-gray-300'}`}>
                            {t.ic} {t.l}
                            {t.n != null && <span className="ml-1 px-1.5 py-0.5 bg-white/10 rounded text-[10px]">{t.n}</span>}
                        </button>
                    ))}
                </div>

                {/* ══════════ TAB: FINDINGS ══════════ */}
                {tab === 'findings' && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
                        <div className="flex flex-wrap gap-2">
                            {['all','critical','high','medium','info'].map(f => {
                                const cnt = f === 'all' ? total : ((bk as any)[f] ?? 0)
                                const on = filter === f
                                return (
                                    <button key={f} onClick={() => setFilter(f)}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all flex items-center gap-1.5 ${on ? 'bg-white/10 border-white/30 text-white' : 'border-white/5 text-gray-600 hover:border-white/15 hover:text-gray-400'}`}>
                                        {f.charAt(0).toUpperCase() + f.slice(1)}
                                        <span className={`text-[10px] px-1 rounded ${on ? 'bg-white/20' : 'bg-white/5'}`}>{cnt}</span>
                                    </button>
                                )
                            })}
                        </div>
                        <div className="space-y-2">
                            {filtered.map((f, i) => <FindingCard key={`${f.id}-${i}`} finding={f} open={i === 0 && f.severity === 'critical'} />)}
                            {filtered.length === 0 && (
                                <div className="text-center py-16 text-gray-600">
                                    <Shield size={48} className="mx-auto mb-4 opacity-20" />
                                    <p className="text-sm">No findings match the selected filter.</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* ══════════ TAB: OWASP ══════════ */}
                {tab === 'owasp' && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <div className="glass-card p-6">
                                <h3 className="text-sm font-black text-gray-300 mb-4 flex items-center gap-2"><Target size={16} className="text-purple-400" /> OWASP M1–M10 Radar</h3>
                                <div className="h-72">
                                    <ResponsiveContainer>
                                        <RadarChart data={owaspData}>
                                            <PolarGrid stroke="rgba(255,255,255,0.08)" />
                                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#7878a0', fontSize: 11, fontWeight: 700 }} />
                                            <PolarRadiusAxis tick={{ fill: '#4a4a6a', fontSize: 9 }} />
                                            <Radar name="Findings" dataKey="count" stroke="#7c5cfc" fill="#7c5cfc" fillOpacity={0.25} strokeWidth={2} />
                                            <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #252540', borderRadius: 8, fontSize: 11 }}
                                                     formatter={(v: number, _: string, p: any) => [v, p.payload.name]} />
                                        </RadarChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>
                            <div className="glass-card p-6">
                                <h3 className="text-sm font-black text-gray-300 mb-4 flex items-center gap-2"><BarChart3 size={16} className="text-cyan-400" /> Finding Distribution</h3>
                                <div className="h-72">
                                    <ResponsiveContainer>
                                        <BarChart data={owaspData} layout="vertical">
                                            <XAxis type="number" tick={{ fill: '#7878a0', fontSize: 10 }} />
                                            <YAxis type="category" dataKey="subject" tick={{ fill: '#7878a0', fontSize: 10 }} width={35} />
                                            <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #252540', borderRadius: 8, fontSize: 11 }}
                                                     formatter={(v: number, _: string, p: any) => [v, p.payload.name]} />
                                            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                                                {owaspData.map((e, i) => (
                                                    <Cell key={i} fill={e.max_severity === 'critical' ? '#ef4444' : e.max_severity === 'high' ? '#f97316' : e.max_severity === 'medium' ? '#eab308' : e.count > 0 ? '#3b82f6' : '#1e1e3a'} />
                                                ))}
                                            </Bar>
                                        </BarChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                            {owaspData.map(cat => {
                                const sc = cat.max_severity === 'critical' ? 'red' : cat.max_severity === 'high' ? 'orange' : cat.max_severity === 'medium' ? 'yellow' : cat.count > 0 ? 'blue' : 'green'
                                return (
                                    <NeonCard key={cat.subject} glowColor={sc as any} className="p-4 text-center">
                                        <div className="text-gray-500 mb-2 flex justify-center">{OWASP_ICONS[cat.subject] || <Shield size={16} />}</div>
                                        <p className="text-xs font-black text-gray-400 mb-0.5">{cat.subject}</p>
                                        <p className="text-[9px] text-gray-600 leading-tight h-7 flex items-center justify-center">{cat.name}</p>
                                        <p className={`text-2xl font-black mt-1 ${cat.count > 0 ? 'text-white' : 'text-gray-800'}`}>{cat.count}</p>
                                        {cat.max_severity !== 'none' && <SevPill severity={cat.max_severity} />}
                                    </NeonCard>
                                )
                            })}
                        </div>
                    </motion.div>
                )}

                {/* ══════════ TAB: AI ══════════ */}
                {tab === 'ai' && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">

                        {aiLoading && (
                            <div className="glass-card p-12 flex flex-col items-center gap-4">
                                <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}>
                                    <Brain size={40} className="text-purple-400" />
                                </motion.div>
                                <p className="text-sm text-gray-400">AI is analyzing the security report…</p>
                                <p className="text-[10px] text-gray-600">This may take 10-30 seconds</p>
                            </div>
                        )}

                        {ai?.error && !ai.available && (
                            <div className="glass-card p-8 text-center space-y-3">
                                <Brain size={40} className="mx-auto text-gray-600" />
                                <p className="text-sm text-gray-400">AI analysis is not available</p>
                                <p className="text-xs text-gray-600">{ai.error}</p>
                                <p className="text-[10px] text-gray-700">Set GROQ_API_KEY or GEMINI_API_KEY to enable AI features.</p>
                            </div>
                        )}

                        {ai && !ai.error && (<>
                            {ai.executive_summary && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-purple-400 mb-3 flex items-center gap-2">
                                        <Brain size={16} /> AI Executive Summary
                                        {ai.provider && <span className="text-[10px] text-gray-600 font-normal ml-2">powered by {ai.provider}</span>}
                                    </h3>
                                    <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{ai.executive_summary}</p>
                                </div>
                            )}

                            {ai.threat_model && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-red-400 mb-4 flex items-center gap-2"><Target size={16} /> Threat Model</h3>
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div>
                                            <p className="text-[10px] text-gray-500 uppercase font-bold mb-2">Attack Vectors</p>
                                            <ul className="space-y-1">{ai.threat_model.attack_vectors?.map((v, i) => (
                                                <li key={i} className="text-xs text-gray-400 flex items-start gap-1.5"><Zap size={10} className="text-red-400 mt-0.5 shrink-0" />{v}</li>
                                            ))}</ul>
                                        </div>
                                        <div>
                                            <p className="text-[10px] text-gray-500 uppercase font-bold mb-2">Threat Actors</p>
                                            <ul className="space-y-1">{ai.threat_model.threat_actors?.map((a, i) => (
                                                <li key={i} className="text-xs text-gray-400 flex items-start gap-1.5"><AlertTriangle size={10} className="text-orange-400 mt-0.5 shrink-0" />{a}</li>
                                            ))}</ul>
                                        </div>
                                        <div>
                                            <p className="text-[10px] text-gray-500 uppercase font-bold mb-2">Impact Assessment</p>
                                            <p className="text-xs text-gray-400 leading-relaxed">{ai.threat_model.impact_assessment}</p>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {(ai.critical_chains?.length ?? 0) > 0 && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-orange-400 mb-4 flex items-center gap-2"><Activity size={16} /> Vulnerability Chains</h3>
                                    <div className="space-y-3">
                                        {ai.critical_chains!.map((ch, i) => (
                                            <div key={i} className="bg-white/[0.02] rounded-lg p-4 border border-white/5">
                                                <div className="flex items-center gap-2 mb-2">
                                                    <span className="text-xs font-black text-white">{ch.name}</span>
                                                    <span className="text-[10px] text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">{ch.risk}</span>
                                                    <span className="text-[10px] text-gray-500">{ch.exploit_difficulty}</span>
                                                </div>
                                                <p className="text-xs text-gray-400">{ch.chain}</p>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {(ai.prioritized_fixes?.length ?? 0) > 0 && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-emerald-400 mb-4 flex items-center gap-2"><TrendingDown size={16} /> Prioritized Fix Plan</h3>
                                    <div className="space-y-3">
                                        {ai.prioritized_fixes!.map((fx, i) => (
                                            <div key={i} className="flex items-start gap-3 bg-white/[0.02] rounded-lg p-4 border border-white/5">
                                                <span className="text-lg font-black text-emerald-400 bg-emerald-500/10 w-8 h-8 rounded-lg flex items-center justify-center shrink-0">{fx.priority}</span>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-xs font-bold text-white mb-1">{fx.finding}</p>
                                                    <p className="text-xs text-gray-500 mb-2">{fx.reason}</p>
                                                    <span className="text-[10px] text-gray-600 bg-white/5 px-1.5 py-0.5 rounded">Effort: {fx.effort}</span>
                                                    {fx.code_fix && <pre className="mt-2 bg-[#0d0d1a] rounded p-2 text-[10px] text-gray-400 font-mono overflow-x-auto whitespace-pre-wrap">{fx.code_fix}</pre>}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {(ai.security_recommendations?.length ?? 0) > 0 && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-cyan-400 mb-4 flex items-center gap-2"><ShieldCheck size={16} /> Security Recommendations</h3>
                                    <ul className="space-y-2">
                                        {ai.security_recommendations!.map((r, i) => (
                                            <li key={i} className="text-xs text-gray-400 flex items-start gap-2"><CheckCircle size={12} className="text-cyan-400 mt-0.5 shrink-0" />{r}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {ai.compliance_notes && (
                                <div className="glass-card p-6">
                                    <h3 className="text-sm font-black text-yellow-400 mb-3 flex items-center gap-2"><FileText size={16} /> Compliance Notes</h3>
                                    <p className="text-xs text-gray-400 leading-relaxed whitespace-pre-wrap">{ai.compliance_notes}</p>
                                </div>
                            )}
                        </>)}
                    </motion.div>
                )}

            </main>
        </div>
    )
}
