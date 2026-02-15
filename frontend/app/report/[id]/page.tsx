'use client'

import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Shield, ShieldAlert, ShieldCheck, AlertTriangle, Info,
    FileText, ArrowLeft, Download, Code, ChevronDown,
    Bug, Lock, Wifi, Eye, Smartphone, Database, Key, Layers,
    BarChart3, Target, Clock, Package, FileCode,
    CheckCircle, XCircle, AlertCircle, Brain, X, Sparkles,
    Send, MessageCircle, CornerDownLeft, Loader2, Search
} from 'lucide-react'
import {
    RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
    PieChart, Pie
} from 'recharts'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import NeonCard from '../../components/NeonCard'
import CyberBackground from '../../components/CyberBackground'
import { apiUrl } from '../../lib/api'
import { exportPDF, exportJSON, exportCSV } from '../../lib/exportReport'

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

interface ChatMessage {
    role: 'user' | 'assistant' | 'system'
    content: string
    timestamp: number
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

/* shared markdown renderer config */
const mdComponents = {
    p: ({children}: any) => <p className="mb-2 last:mb-0">{children}</p>,
    strong: ({children}: any) => <strong className="text-white font-semibold">{children}</strong>,
    em: ({children}: any) => <em className="text-purple-300">{children}</em>,
    h1: ({children}: any) => <h3 className="text-sm font-bold text-white mt-3 mb-1.5">{children}</h3>,
    h2: ({children}: any) => <h3 className="text-sm font-bold text-white mt-3 mb-1.5">{children}</h3>,
    h3: ({children}: any) => <h4 className="text-[13px] font-bold text-white mt-2.5 mb-1">{children}</h4>,
    ul: ({children}: any) => <ul className="list-disc list-outside ml-4 mb-2 space-y-0.5">{children}</ul>,
    ol: ({children}: any) => <ol className="list-decimal list-outside ml-4 mb-2 space-y-0.5">{children}</ol>,
    li: ({children}: any) => <li className="text-gray-300">{children}</li>,
    code: ({className, children, ...props}: any) => {
        const isBlock = className?.includes('language-')
        if (isBlock) {
            return (
                <div className="my-2 rounded-lg overflow-hidden border border-white/10">
                    <div className="bg-white/[0.06] px-3 py-1 text-[9px] text-gray-500 font-mono border-b border-white/5">
                        {className?.replace('language-', '') || 'code'}
                    </div>
                    <pre className="bg-[#0d0d1a] p-3 overflow-x-auto"><code className="text-[11px] font-mono text-emerald-300 leading-relaxed">{children}</code></pre>
                </div>
            )
        }
        return <code className="bg-white/10 text-purple-300 px-1.5 py-0.5 rounded text-[11px] font-mono" {...props}>{children}</code>
    },
    pre: ({children}: any) => <>{children}</>,
    blockquote: ({children}: any) => <blockquote className="border-l-2 border-yellow-500/50 pl-3 my-2 text-yellow-200/80 italic">{children}</blockquote>,
    a: ({href, children}: any) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-purple-400 underline hover:text-purple-300">{children}</a>,
    table: ({children}: any) => <div className="overflow-x-auto my-2"><table className="text-[10px] border-collapse w-full">{children}</table></div>,
    th: ({children}: any) => <th className="border border-white/10 bg-white/5 px-2 py-1 text-left text-gray-300 font-bold">{children}</th>,
    td: ({children}: any) => <td className="border border-white/10 px-2 py-1 text-gray-400">{children}</td>,
}

function FindingCard({ finding, open = false, findingIndex, scanId }: { finding: Finding; open?: boolean; findingIndex: number; scanId: string }) {
    const [exp, setExp] = useState(open)
    const [aiRem, setAiRem] = useState<string | null>(null)
    const [aiRemLoading, setAiRemLoading] = useState(false)
    const c = SEV[finding.severity] || SEV.info

    const handleRemediate = async () => {
        if (aiRem || aiRemLoading) return
        setAiRemLoading(true)
        try {
            const res = await fetch(apiUrl('/api/ai/remediate'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: scanId, finding_index: findingIndex })
            })
            if (!res.ok) throw new Error('Failed')
            const data = await res.json()
            setAiRem(data.remediation || 'No remediation available.')
        } catch {
            setAiRem('Failed to generate AI remediation. Please try again.')
        } finally {
            setAiRemLoading(false)
        }
    }

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

                            {/* AI Fix Button */}
                            <button
                                onClick={handleRemediate}
                                disabled={aiRemLoading || !!aiRem}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-lg transition-colors text-[11px] font-bold disabled:opacity-50"
                            >
                                {aiRemLoading ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                                {aiRem ? 'AI Fix Generated' : aiRemLoading ? 'Generating fix…' : 'Fix with AI'}
                            </button>

                            {/* AI Remediation Response */}
                            {aiRem && (
                                <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                                    className="bg-purple-500/[0.05] border border-purple-500/20 rounded-lg p-4">
                                    <h4 className="text-purple-400 text-[10px] font-black mb-2 flex items-center gap-1.5 uppercase tracking-widest"><Sparkles size={12} /> AI-Powered Fix</h4>
                                    <div className="text-xs text-gray-300 leading-relaxed chat-md">
                                        <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                                            {aiRem}
                                        </ReactMarkdown>
                                    </div>
                                </motion.div>
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
    const [search, setSearch]       = useState('')
    const [tab, setTab]             = useState<'findings' | 'owasp'>('findings')
    const [toast, setToast]         = useState<{ msg: string; show: boolean }>({ msg: '', show: false })
    const [ai, setAi]               = useState<AIAnalysis | null>(null)
    const [aiLoading, setAiLoading] = useState(false)
    const [aiOpen, setAiOpen]       = useState(false)
    const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
    const [chatInput, setChatInput] = useState('')
    const [chatSending, setChatSending] = useState(false)
    const chatEndRef = useRef<HTMLDivElement>(null)
    const chatInputRef = useRef<HTMLTextAreaElement>(null)
    const [exportOpen, setExportOpen] = useState(false)
    const exportRef = useRef<HTMLDivElement>(null)

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
        if (!aiOpen || ai || aiLoading || !report) return
        ;(async () => {
            setAiLoading(true)
            try {
                const r = await fetch(apiUrl(`/api/ai/analyze/${params.id}`))
                setAi(r.ok ? await r.json() : { error: 'AI analysis unavailable', available: false })
            } catch { setAi({ error: 'Failed to reach AI endpoint', available: false }) }
            finally { setAiLoading(false) }
        })()
    }, [aiOpen, ai, aiLoading, report, params.id])

    /* auto-scroll chat */
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [chatMessages, chatSending])

    /* focus input when drawer opens */
    useEffect(() => {
        if (aiOpen && !aiLoading && !chatSending) {
            setTimeout(() => chatInputRef.current?.focus(), 300)
        }
    }, [aiOpen, aiLoading, chatSending])

    /* close export dropdown on outside click */
    useEffect(() => {
        if (!exportOpen) return
        const handler = (e: MouseEvent) => {
            if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false)
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [exportOpen])

    /* send chat message */
    const sendChat = useCallback(async (msg?: string) => {
        const text = (msg ?? chatInput).trim()
        if (!text || chatSending || !params.id) return

        setChatInput('')
        setChatMessages(prev => [...prev, { role: 'user', content: text, timestamp: Date.now() }])
        setChatSending(true)

        try {
            const res = await fetch(apiUrl('/api/ai/chat'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, scan_id: params.id }),
            })
            if (!res.ok) throw new Error('Chat failed')
            const data = await res.json()
            setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: data.response || 'No response received.',
                timestamp: Date.now()
            }])
        } catch {
            setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: 'Sorry, I couldn\'t process that request. Please check if the AI service is configured.',
                timestamp: Date.now()
            }])
        } finally {
            setChatSending(false)
            setTimeout(() => chatInputRef.current?.focus(), 100)
        }
    }, [chatInput, chatSending, params.id])

    /* show toast helper */
    const showToast = useCallback((msg: string) => {
        setToast({ msg, show: true })
        setTimeout(() => setToast(t => ({ ...t, show: false })), 3000)
    }, [])

    /* derived */
    const score      = report?.security_score?.score ?? 0
    const grade      = report?.security_score?.grade ?? '?'
    const bk         = report?.severity_breakdown ?? {}
    const findings   = report?.findings ?? []
    const meta       = report?.metadata ?? {}
    const total      = report?.total_findings ?? findings.length

    const filtered = useMemo(() => {
        const q = search.toLowerCase().trim()
        return findings
            .filter(f => filter === 'all' || f.severity === filter)
            .filter(f => !q || f.name?.toLowerCase().includes(q) || f.description?.toLowerCase().includes(q) || f.location?.toLowerCase().includes(q) || f.evidence?.toLowerCase().includes(q) || f.id?.toLowerCase().includes(q))
            .sort((a, b) => (SEV[a.severity]?.order ?? 3) - (SEV[b.severity]?.order ?? 3))
    }, [findings, filter, search])

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
        <div className="min-h-screen bg-[#0a0a12] text-white selection:bg-purple-500/30 pb-20 overflow-x-hidden">
            <CyberBackground />

            {/* NAV */}
            <nav className="border-b border-white/10 bg-black/60 backdrop-blur-xl sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
                    <Link href="/" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors text-sm">
                        <ArrowLeft size={18} /> Back
                    </Link>
                    <div className="flex items-center gap-3">
                        <span className="text-[10px] text-gray-600 font-mono hidden md:inline">ID: {report.scan_id}</span>
                        <div className="relative" ref={exportRef}>
                            <button onClick={() => setExportOpen(o => !o)}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded-lg transition-colors text-xs font-bold">
                                <Download size={14} /> Export <ChevronDown size={12} className={`transition-transform ${exportOpen ? 'rotate-180' : ''}`} />
                            </button>
                            <AnimatePresence>
                                {exportOpen && (
                                    <motion.div
                                        initial={{ opacity: 0, y: -6, scale: 0.95 }}
                                        animate={{ opacity: 1, y: 0, scale: 1 }}
                                        exit={{ opacity: 0, y: -6, scale: 0.95 }}
                                        transition={{ duration: 0.15 }}
                                        className="absolute right-0 mt-2 w-52 bg-[#0c0c14] border border-white/10 rounded-xl shadow-2xl overflow-hidden z-[60]">
                                        <div className="py-1">
                                            <button onClick={() => { exportPDF(report as any); setExportOpen(false); showToast('PDF report downloaded') }}
                                                className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                                                <FileText size={14} className="text-red-400" />
                                                <div className="text-left"><div className="font-bold">PDF Report</div><div className="text-[10px] text-gray-600">Professional formatted report</div></div>
                                            </button>
                                            <button onClick={() => { exportJSON(report as any); setExportOpen(false); showToast('JSON data downloaded') }}
                                                className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                                                <Code size={14} className="text-yellow-400" />
                                                <div className="text-left"><div className="font-bold">JSON Data</div><div className="text-[10px] text-gray-600">Machine-readable format</div></div>
                                            </button>
                                            <button onClick={() => { exportCSV(report as any); setExportOpen(false); showToast('CSV findings downloaded') }}
                                                className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                                                <BarChart3 size={14} className="text-green-400" />
                                                <div className="text-left"><div className="font-bold">CSV Findings</div><div className="text-[10px] text-gray-600">Spreadsheet compatible</div></div>
                                            </button>
                                            <div className="border-t border-white/5 my-1" />
                                            <a href={apiUrl(`/api/report/${params.id}/download`)}
                                                onClick={() => { setExportOpen(false); showToast('HTML report downloaded') }}
                                                className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                                                <Download size={14} className="text-cyan-400" />
                                                <div className="text-left"><div className="font-bold">HTML Report</div><div className="text-[10px] text-gray-600">Standalone web report</div></div>
                                            </a>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6 py-6 sm:py-8 space-y-6 sm:space-y-8">

                {/* ══════════ HERO ══════════ */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-5 sm:p-6 md:p-8">
                    <div className="flex flex-col md:flex-row items-center gap-6 md:gap-8">
                        <ScoreRing score={score} grade={grade} />

                        <div className="flex-1 text-center md:text-left space-y-3 min-w-0">
                            <div>
                                <h1 className="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{report.apk_filename || report.package || 'Unknown APK'}</h1>
                                <p className="text-xs sm:text-sm text-gray-500 font-mono truncate">{report.package}</p>
                            </div>
                            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl line-clamp-3">{report.security_score?.summary}</p>
                            <div className="flex flex-wrap justify-center md:justify-start gap-2 sm:gap-3 pt-2">
                                <span className={`text-[11px] sm:text-xs font-bold px-3 py-1 rounded-full border ${gs.ring} ${gs.text} bg-white/5`}>
                                    {report.security_score?.risk_level} Risk
                                </span>
                                <span className="text-[11px] sm:text-xs text-gray-500 px-3 py-1 rounded-full border border-white/10 bg-white/5">
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
                        <div className="flex flex-col sm:flex-row gap-3">
                            <div className="relative flex-1 max-w-xs">
                                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
                                <input
                                    type="text"
                                    value={search}
                                    onChange={e => setSearch(e.target.value)}
                                    placeholder="Search findings…"
                                    className="w-full bg-white/[0.04] border border-white/10 focus:border-purple-500/40 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 outline-none transition-colors"
                                />
                            </div>
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
                        </div>
                        <div className="space-y-2">
                            {filtered.map((f, i) => {
                                const origIdx = findings.indexOf(f)
                                return <FindingCard key={`${f.id}-${i}`} finding={f} open={i === 0 && f.severity === 'critical'} findingIndex={origIdx} scanId={params.id as string} />
                            })}
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
                                                     formatter={((v: any, _: any, p: any) => [v ?? 0, p?.payload?.name]) as any} />
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
                                                     formatter={((v: any, _: any, p: any) => [v ?? 0, p?.payload?.name]) as any} />
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

            </main>

            {/* ═══════ FLOATING AI CHAT BUTTON ═══════ */}
            {!aiOpen && (
                <motion.button
                    onClick={() => setAiOpen(true)}
                    className="fixed bottom-6 right-6 z-40 group"
                    whileHover={{ scale: 1.08 }}
                    whileTap={{ scale: 0.92 }}
                    title="AI Security Chat"
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ type: 'spring', damping: 15 }}
                >
                    <div className="w-14 h-14 rounded-full bg-gradient-to-br from-purple-600 via-indigo-600 to-purple-700 text-white shadow-xl flex items-center justify-center animate-float-pulse relative">
                        <MessageCircle size={24} />
                        <span className="absolute -top-0.5 -right-0.5 flex h-3.5 w-3.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-green-400 border-2 border-[#0a0a12]" />
                        </span>
                    </div>
                    <span className="absolute bottom-full right-0 mb-2 px-2.5 py-1 bg-white/10 backdrop-blur-xl border border-white/10 rounded-lg text-[10px] text-gray-300 font-bold whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                        Ask AI about this scan
                    </span>
                </motion.button>
            )}

            {/* ═══════ AI CHAT DRAWER ═══════ */}
            <AnimatePresence>
                {aiOpen && (
                    <>
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 lg:hidden"
                            onClick={() => setAiOpen(false)}
                        />
                        <motion.aside
                            initial={{ x: '100%' }}
                            animate={{ x: 0 }}
                            exit={{ x: '100%' }}
                            transition={{ type: 'spring', damping: 28, stiffness: 260 }}
                            className="fixed right-0 top-0 h-full w-full sm:w-[420px] lg:w-[440px] bg-[#0c0c18]/98 backdrop-blur-2xl border-l border-white/10 z-50 flex flex-col shadow-2xl shadow-purple-900/20"
                        >
                            {/* ── Header ── */}
                            <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 shrink-0">
                                <div className="flex items-center gap-2.5">
                                    <div className="p-1.5 rounded-lg bg-gradient-to-br from-purple-500/20 to-indigo-500/20">
                                        <Brain size={18} className="text-purple-400" />
                                    </div>
                                    <div>
                                        <h2 className="text-sm font-black text-white">DroidSec AI</h2>
                                        <p className="text-[9px] text-gray-500">{ai?.provider ? `powered by ${ai.provider}` : 'Security Assistant'}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-1">
                                    {chatMessages.length > 0 && (
                                        <button onClick={() => setChatMessages([])}
                                            className="px-2 py-1 rounded text-[10px] text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-colors font-bold">
                                            Clear
                                        </button>
                                    )}
                                    <button onClick={() => setAiOpen(false)}
                                        className="p-1.5 rounded-lg hover:bg-white/10 text-gray-500 hover:text-white transition-colors">
                                        <X size={18} />
                                    </button>
                                </div>
                            </div>

                            {/* ── Chat Body ── */}
                            <div className="flex-1 overflow-y-auto ai-drawer">
                                <div className="p-4 space-y-3">

                                    {/* Deep analysis loading */}
                                    {aiLoading && (
                                        <div className="flex flex-col items-center justify-center py-12 gap-3">
                                            <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}>
                                                <Brain size={32} className="text-purple-400" />
                                            </motion.div>
                                            <p className="text-xs text-gray-400">Loading AI analysis…</p>
                                        </div>
                                    )}

                                    {/* AI deep analysis error (non-blocking) */}
                                    {ai?.error && !ai.available && chatMessages.length === 0 && (
                                        <div className="text-center py-4 space-y-1 opacity-60">
                                            <p className="text-[10px] text-gray-500">Deep analysis unavailable — chat still works</p>
                                        </div>
                                    )}

                                    {/* Deep analysis summary card (collapsed) */}
                                    {ai && !ai.error && ai.executive_summary && chatMessages.length === 0 && (
                                        <div className="bg-purple-500/[0.05] rounded-xl p-3.5 border border-purple-500/20">
                                            <div className="flex items-center gap-1.5 mb-2">
                                                <Sparkles size={12} className="text-purple-400" />
                                                <span className="text-[10px] font-black text-purple-400 uppercase tracking-wider">AI Analysis Summary</span>
                                            </div>
                                            <p className="text-[11px] text-gray-300 leading-relaxed line-clamp-4">{ai.executive_summary}</p>
                                        </div>
                                    )}

                                    {/* Welcome message when no chat yet */}
                                    {chatMessages.length === 0 && !aiLoading && (
                                        <div className="space-y-4 pt-2">
                                            <div className="flex gap-2.5">
                                                <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center shrink-0 mt-0.5">
                                                    <Brain size={14} className="text-white" />
                                                </div>
                                                <div className="bg-white/[0.04] rounded-2xl rounded-tl-sm px-3.5 py-2.5 border border-white/5 max-w-[85%]">
                                                    <p className="text-[11px] text-gray-300 leading-relaxed">
                                                        Hi! I&apos;m your AI security assistant. I&apos;ve analyzed <strong className="text-white">{report?.apk_filename || 'this APK'}</strong> and found <strong className="text-white">{total} security findings</strong>.
                                                    </p>
                                                    <p className="text-[11px] text-gray-400 leading-relaxed mt-1.5">
                                                        Ask me anything — vulnerability details, code fixes, exploitation scenarios, or OWASP mappings.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Chat messages */}
                                    {chatMessages.map((msg, i) => (
                                        <div key={i} className={`flex gap-2.5 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                            {msg.role === 'assistant' && (
                                                <div className="w-6 h-6 rounded-full bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center shrink-0 mt-0.5">
                                                    <Brain size={12} className="text-white" />
                                                </div>
                                            )}
                                            <div className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 border ${
                                                msg.role === 'user'
                                                    ? 'bg-purple-600/20 border-purple-500/20 rounded-tr-sm'
                                                    : 'bg-white/[0.04] border-white/5 rounded-tl-sm'
                                            }`}>
                                                <div className="text-[12px] text-gray-300 leading-relaxed break-words chat-md">
                                                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                                                        {msg.content}
                                                    </ReactMarkdown>
                                                </div>
                                            </div>
                                            {msg.role === 'user' && (
                                                <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center shrink-0 mt-0.5">
                                                    <span className="text-[10px] font-bold text-gray-400">You</span>
                                                </div>
                                            )}
                                        </div>
                                    ))}

                                    {/* Typing indicator */}
                                    {chatSending && (
                                        <div className="flex gap-2.5">
                                            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center shrink-0 mt-0.5">
                                                <Brain size={12} className="text-white" />
                                            </div>
                                            <div className="bg-white/[0.04] rounded-2xl rounded-tl-sm px-4 py-3 border border-white/5">
                                                <div className="flex gap-1">
                                                    {[0,1,2].map(i => (
                                                        <motion.div key={i} className="w-1.5 h-1.5 bg-purple-400 rounded-full"
                                                            animate={{ opacity: [0.3, 1, 0.3], y: [0, -3, 0] }}
                                                            transition={{ repeat: Infinity, duration: 1, delay: i * 0.15 }}
                                                        />
                                                    ))}
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    <div ref={chatEndRef} />
                                </div>

                            </div>

                            {/* ── Chat Input ── */}
                            <div className="shrink-0 border-t border-white/10 p-3 bg-[#0a0a14]/80">
                                <div className="flex gap-2 items-end">
                                    <div className="flex-1 relative">
                                        <textarea
                                            ref={chatInputRef}
                                            value={chatInput}
                                            onChange={(e) => setChatInput(e.target.value)}
                                            onKeyDown={(e) => {
                                                if (e.key === 'Enter' && !e.shiftKey) {
                                                    e.preventDefault()
                                                    sendChat()
                                                }
                                            }}
                                            placeholder="Ask about vulnerabilities, code fixes…"
                                            rows={1}
                                            className="w-full bg-white/[0.04] border border-white/10 focus:border-purple-500/40 rounded-xl px-3.5 py-2.5 text-[12px] text-gray-200 placeholder-gray-600 outline-none resize-none transition-colors"
                                            style={{ maxHeight: '100px' }}
                                            disabled={chatSending}
                                        />
                                        <div className="absolute right-2 bottom-1.5 text-[8px] text-gray-700">
                                            <CornerDownLeft size={10} className="inline mr-0.5" />enter
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => sendChat()}
                                        disabled={!chatInput.trim() || chatSending}
                                        className="w-9 h-9 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:bg-white/5 disabled:text-gray-700 text-white flex items-center justify-center transition-colors shrink-0"
                                    >
                                        {chatSending ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                                    </button>
                                </div>
                            </div>
                        </motion.aside>
                    </>
                )}
            </AnimatePresence>

            {/* ═══════ TOAST ═══════ */}
            <AnimatePresence>
                {toast.show && (
                    <motion.div
                        initial={{ opacity: 0, y: 40, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 20, scale: 0.95 }}
                        transition={{ duration: 0.2 }}
                        className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] px-5 py-2.5 bg-emerald-500/20 border border-emerald-500/40 backdrop-blur-xl rounded-xl text-emerald-300 text-xs font-bold flex items-center gap-2 shadow-2xl"
                    >
                        <CheckCircle size={14} /> {toast.msg}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}
