'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import {
    Shield, ShieldAlert, ShieldCheck, AlertTriangle,
    FileText, ArrowLeft, Download, Code
} from 'lucide-react'
import NeonCard from '../../components/NeonCard'
import CyberBackground from '../../components/CyberBackground'
import { apiUrl } from '../../lib/api'

interface Finding {
    id: string
    name: string
    description: string
    severity: string
    confidence_score?: number
    evidence?: string
    location?: string
    owasp?: string
    remediation?: string
    context?: string
}

interface Breakdown {
    critical?: number
    high?: number
    medium?: number
    info?: number
}

interface OWASPCategory {
    name: string
    count: number
    max_severity: string
}

interface Report {
    scan_id: string
    package?: string
    timestamp?: string
    total_findings?: number
    security_score?: {
        score: number
        grade: string
        risk_level: string
        summary?: string
    }
    severity_breakdown?: Breakdown
    owasp_coverage?: Record<string, OWASPCategory>
    findings?: Finding[]
}

export default function ReportPage() {
    const params = useParams()
    const [report, setReport] = useState<Report | null>(null)
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState('all')

    useEffect(() => {
        if (!params.id) return

        const fetchReport = async () => {
            try {
                const res = await fetch(apiUrl(`/api/report/${params.id}`))
                if (!res.ok) throw new Error("Report not found")
                const data = await res.json()
                setReport(data)
            } catch (err) {
                console.error(err)
            } finally {
                setLoading(false)
            }
        }

        fetchReport()
    }, [params.id])

    if (loading) return (
        <div className="min-h-screen bg-[#0a0a12] flex items-center justify-center text-green-400 font-mono">
            Scanning databanks...
        </div>
    )

    if (!report) return (
        <div className="min-h-screen bg-[#0a0a12] flex flex-col items-center justify-center text-red-500 font-mono">
            <AlertTriangle size={48} className="mb-4" />
            <h1 className="text-2xl">REPORT NOT FOUND</h1>
            <Link href="/" className="mt-4 text-green-400 underline hover:text-green-300">Return to Dashboard</Link>
        </div>
    )

    const score = report.security_score?.score || 0
    const grade = report.security_score?.grade || '?'
    const breakdown = report.severity_breakdown || {}
    const findings = report.findings || []
    const timestampText = report.timestamp ? new Date(report.timestamp).toLocaleString() : "N/A"
    const totalFindings = report.total_findings ?? findings.length

    // Support pre-filtering based on query but default to all
    const filteredFindings = findings.filter((f: Finding) =>
        filter === 'all' ? true : f.severity === filter
    )

    const getGradeColor = (g: string) => {
        if (g === 'A') return 'text-green-400 border-green-500 shadow-[0_0_30px_rgba(34,197,94,0.4)]'
        if (g === 'B') return 'text-yellow-400 border-yellow-500 shadow-[0_0_30px_rgba(234,179,8,0.4)]'
        if (g === 'C') return 'text-orange-400 border-orange-500 shadow-[0_0_30px_rgba(249,115,22,0.4)]'
        return 'text-red-500 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.4)]'
    }

    return (
        <div className="min-h-screen bg-[#0a0a12] text-white font-mono selection:bg-green-500/30 pb-20">
            <CyberBackground />

            <nav className="border-b border-white/10 bg-black/40 backdrop-blur sticky top-0 z-50">
                <div className="container mx-auto px-4 py-4 flex items-center justify-between">
                    <Link href="/" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
                        <ArrowLeft size={20} /> <span className="hidden md:inline">Back to Dashboard</span>
                    </Link>
                    <div className="flex items-center gap-4">
                        <span className="text-sm text-gray-400 hidden md:inline">Scan ID: {report.scan_id}</span>
                        <a href={apiUrl(`/api/report/${params.id}/download`)} className="flex items-center gap-2 px-4 py-2 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/50 rounded transition-colors text-sm">
                            <Download size={16} /> Export HTML
                        </a>
                    </div>
                </div>
            </nav>

            <main className="container mx-auto px-4 py-12">
                {/* Technical Overview & Summary */}
                <div className="grid grid-cols-1 lg:grid-cols-4 gap-8 mb-12">
                    <div className="lg:col-span-1 space-y-4">
                        <NeonCard glowColor="cyan" className="p-4 h-full">
                            <h3 className="text-sm font-bold text-cyan-400 mb-4 flex items-center gap-2">
                                <FileText size={16} /> APK METADATA
                            </h3>
                            <div className="space-y-3 text-xs">
                                <div>
                                    <p className="text-gray-500 uppercase">Package Name</p>
                                    <p className="text-white break-all">{report.package || "N/A"}</p>
                                </div>
                                <div>
                                    <p className="text-gray-500 uppercase">Scan Timestamp</p>
                                    <p className="text-white">{timestampText}</p>
                                </div>
                                <div>
                                    <p className="text-gray-500 uppercase">Analysis Engine</p>
                                    <p className="text-white">DroidSec v1.0.0 (FastAPI)</p>
                                </div>
                            </div>
                        </NeonCard>
                    </div>

                    <div className="lg:col-span-3">
                        <NeonCard glowColor="green" className="p-6 h-full">
                            <h3 className="text-sm font-bold text-green-400 mb-4 flex items-center gap-2">
                                <ShieldCheck size={16} /> EXECUTIVE TECHNICAL SUMMARY
                            </h3>
                            <p className="text-gray-300 leading-relaxed text-sm">
                                {report.security_score?.summary || "No automated summary available for this report."}
                            </p>
                            <div className="mt-6 flex flex-wrap gap-4 pt-4 border-t border-white/5">
                                <div className="flex flex-col">
                                    <span className="text-xs text-gray-500 uppercase">Total Vulns</span>
                                    <span className="text-xl font-bold text-white">{totalFindings}</span>
                                </div>
                                <div className="flex flex-col">
                                    <span className="text-xs text-gray-500 uppercase">Risk Level</span>
                                    <span className={`text-xl font-bold ${getGradeColor(grade).split(" ")[0]}`}>
                                        {report.security_score?.risk_level}
                                    </span>
                                </div>
                            </div>
                        </NeonCard>
                    </div>
                </div>

                {/* Score & Breakdown Row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
                    <NeonCard glowColor={grade === 'A' ? 'green' : grade === 'B' ? 'cyan' : 'red'} className="flex flex-col items-center justify-center text-center p-8">
                        <div className={`w-28 h-28 rounded-full border-4 flex items-center justify-center text-5xl font-black mb-4 ${getGradeColor(grade)}`}>
                            {grade}
                        </div>
                        <h2 className="text-2xl font-bold mb-1">Score: {score}/100</h2>
                        <div className="w-full bg-gray-800 h-1.5 rounded-full mt-4 overflow-hidden">
                            <div className={`h-full ${getGradeColor(grade).split(" ")[0].replace("text-", "bg-")}`} style={{ width: `${score}%` }} />
                        </div>
                    </NeonCard>

                    <div className="md:col-span-2 grid grid-cols-2 lg:grid-cols-4 gap-4 text-center">
                        {[
                            { label: 'CRITICAL', count: breakdown.critical || 0, color: 'red', icon: <ShieldAlert size={18} /> },
                            { label: 'HIGH', count: breakdown.high || 0, color: 'orange', icon: <AlertTriangle size={18} /> },
                            { label: 'MEDIUM', count: breakdown.medium || 0, color: 'yellow', icon: <Shield size={18} /> },
                            { label: 'INFO', count: breakdown.info || 0, color: 'blue', icon: <ShieldCheck size={18} /> }
                        ].map((sev) => (
                            <NeonCard key={sev.label} glowColor={sev.color as any} className="flex flex-col justify-center p-4">
                                <div className={`flex items-center justify-center gap-2 mb-2 font-bold text-xs text-${sev.color}-400`}>
                                    {sev.icon} {sev.label}
                                </div>
                                <span className="text-2xl font-black text-white">{sev.count}</span>
                            </NeonCard>
                        ))}
                    </div>
                </div>

                {/* OWASP Coverage Panel */}
                {report.owasp_coverage && (
                    <div className="mb-12">
                        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                            OWASP MOBILE TOP 10 COVERAGE
                        </h2>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                            {Object.entries(report.owasp_coverage).map(([key, cat]) => (
                                <NeonCard key={key} glowColor={cat.count > 0 ? (cat.max_severity === 'critical' || cat.max_severity === 'high' ? 'red' : 'yellow') : 'green'} className="p-3 text-center border-white/5 opacity-80 hover:opacity-100 transition-opacity">
                                    <p className="text-[10px] text-gray-500 font-bold mb-1">{key}</p>
                                    <p className="text-[9px] text-gray-400 truncate mb-2 leading-tight h-6 flex items-center justify-center">{cat.name}</p>
                                    <div className="flex items-center justify-center gap-2">
                                        <span className={`text-lg font-black ${cat.count > 0 ? 'text-white' : 'text-gray-700'}`}>{cat.count}</span>
                                    </div>
                                </NeonCard>
                            ))}
                        </div>
                    </div>
                )}

                {/* Filters */}
                <div className="flex flex-wrap gap-4 mb-8">
                    {['all', 'critical', 'high', 'medium', 'info'].map(f => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-4 py-2 rounded uppercase text-sm font-bold border transition-all ${filter === f
                                ? 'bg-white/10 border-white text-white shadow-[0_0_15px_rgba(255,255,255,0.2)]'
                                : 'border-white/10 text-gray-500 hover:border-white/30 hover:text-gray-300'
                                }`}
                        >
                            {f}
                        </button>
                    ))}
                </div>

                {/* Findings List */}
                <div className="space-y-4">
                    {filteredFindings.map((finding: Finding, idx: number) => (
                        <NeonCard key={idx} glowColor={finding.severity === 'critical' || finding.severity === 'high' ? 'red' : 'cyan'} className="p-0 overflow-hidden">
                            <div className="p-6">
                                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-6">
                                    <div className="flex-1">
                                        <div className="flex flex-wrap items-center gap-2 mb-3">
                                            <span className={`uppercase text-[10px] font-black px-2 py-0.5 rounded border ${finding.severity === 'critical' ? 'border-red-500 bg-red-500/10 text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.2)]' :
                                                    finding.severity === 'high' ? 'border-orange-500 bg-orange-500/10 text-orange-500' :
                                                        finding.severity === 'medium' ? 'border-yellow-500 bg-yellow-500/10 text-yellow-500' :
                                                            'border-blue-500 bg-blue-500/10 text-blue-500'
                                                }`}>
                                                {finding.severity}
                                            </span>
                                            <span className="bg-white/5 text-gray-400 text-[10px] px-2 py-0.5 rounded border border-white/10 font-bold">
                                                {finding.id}
                                            </span>
                                            {finding.owasp && (
                                                <span className="bg-cyan-500/10 text-cyan-400 text-[10px] px-2 py-0.5 rounded border border-cyan-500/30 font-bold">
                                                    OWASP {finding.owasp}
                                                </span>
                                            )}
                                            <div className="flex-1 md:flex-none" />
                                            <div className="flex items-center gap-2 ml-auto">
                                                <span className="text-[10px] text-gray-500 uppercase font-bold">Confidence</span>
                                                <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                                                    <div className="h-full bg-green-500" style={{ width: `${Math.round((finding.confidence_score || 0) * 100)}%` }} />
                                                </div>
                                                <span className="text-[10px] text-gray-300 font-bold">{Math.round((finding.confidence_score || 0) * 100)}%</span>
                                            </div>
                                        </div>
                                        <h3 className="text-xl font-black mb-3 text-white tracking-tight">{finding.name}</h3>
                                        <p className="text-gray-400 text-sm leading-relaxed mb-4 border-l-2 border-white/5 pl-4">{finding.description}</p>
                                    </div>
                                </div>

                                {finding.evidence && (
                                    <div className="mb-6">
                                        <p className="text-[10px] font-black text-gray-500 mb-2 flex items-center gap-2 uppercase tracking-widest">
                                            <Code size={12} /> Technical Evidence
                                        </p>
                                        <div className="bg-black/80 rounded border border-white/5 font-mono text-[11px] overflow-hidden">
                                            <div className="bg-white/5 px-4 py-1 border-b border-white/5 flex justify-between">
                                                <span className="text-gray-500 text-[9px] truncate">{finding.location}</span>
                                                <span className="text-cyan-500/50 text-[9px]">DECOMPILED JALALI/XML</span>
                                            </div>
                                            <div className="p-4 overflow-x-auto custom-scrollbar">
                                                <pre className="text-gray-300 whitespace-pre-wrap">{finding.evidence}</pre>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {finding.remediation && (
                                    <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-5">
                                        <h4 className="text-green-500 text-xs font-black mb-3 flex items-center gap-2 tracking-widest uppercase">
                                            <ShieldCheck size={16} /> RECOMMENDED REMEDIATION
                                        </h4>
                                        <p className="text-gray-300 text-xs leading-relaxed">
                                            {finding.remediation}
                                        </p>
                                    </div>
                                )}
                            </div>

                            <div className="bg-black/40 px-6 py-3 border-t border-white/5 flex items-center justify-between text-[10px] text-gray-500 font-mono">
                                <div className="flex items-center gap-2">
                                    <FileText size={12} /> {finding.location}
                                </div>
                                <div className="uppercase tracking-widest text-white/20">DroidSec Intelligence</div>
                            </div>
                        </NeonCard>
                    ))}

                    {filteredFindings.length === 0 && (
                        <div className="text-center py-12 text-gray-600">
                            No findings match the selected filter.
                        </div>
                    )}
                </div>
            </main>
        </div>
    )
}
