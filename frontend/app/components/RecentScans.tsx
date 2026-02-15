'use client'

import { useState, useEffect } from 'react'
import NeonCard from './NeonCard'
import { Shield, Clock, FileText, ChevronRight } from 'lucide-react'
import Link from 'next/link'
import { apiUrl } from '../lib/api'

const LS_KEY = 'droidsec_recent_scans'

interface RecentReport {
    scan_id: string
    package?: string
    filename?: string
    timestamp: string
    score?: number | string
    grade?: string
    findings_count?: number
}

/** Read cached scans from localStorage */
function getCachedScans(): RecentReport[] {
    if (typeof window === 'undefined') return []
    try {
        const raw = localStorage.getItem(LS_KEY)
        if (raw) return JSON.parse(raw) as RecentReport[]
    } catch { /* ignore */ }
    return []
}

/** Save scans to localStorage (deduplicated, max 20) */
export function saveCachedScans(scans: RecentReport[]) {
    if (typeof window === 'undefined') return
    try {
        const seen = new Set<string>()
        const deduped: RecentReport[] = []
        for (const s of scans) {
            if (!seen.has(s.scan_id)) {
                seen.add(s.scan_id)
                deduped.push(s)
            }
        }
        deduped.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
        localStorage.setItem(LS_KEY, JSON.stringify(deduped.slice(0, 20)))
    } catch { /* ignore */ }
}

/** Add a single scan to the cache (called after upload completes) */
export function addScanToCache(scan: RecentReport) {
    const existing = getCachedScans()
    saveCachedScans([scan, ...existing])
}

export default function RecentScans() {
    const [reports, setReports] = useState<RecentReport[]>([])

    useEffect(() => {
        // 1. Show cached scans instantly
        const cached = getCachedScans()
        if (cached.length > 0) setReports(cached.slice(0, 10))

        // 2. Fetch fresh data from API and merge
        fetch(apiUrl('/api/reports'))
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data) && data.length > 0) {
                    // Merge API data with cache (API is source of truth)
                    const merged = new Map<string, RecentReport>()
                    for (const s of cached) merged.set(s.scan_id, s)
                    for (const s of data) merged.set(s.scan_id, s) // API overwrites
                    const all = Array.from(merged.values())
                    all.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
                    const top = all.slice(0, 10)
                    setReports(top)
                    saveCachedScans(all)
                }
            })
            .catch(err => {
                console.error('Failed to fetch reports:', err)
                // Keep showing cached data on error
            })
    }, [])

    if (reports.length === 0) return null

    return (
        <div className="w-full max-w-4xl mx-auto mt-12">
            <h2 className="text-2xl font-mono font-bold text-green-400 mb-6 flex items-center gap-2">
                <Shield className="animate-pulse" /> RECENT INTELLIGENCE
            </h2>
            <div className="grid gap-4">
                {reports.map((report) => (
                    <Link key={report.scan_id} href={`/report/${report.scan_id}`}>
                        <NeonCard glowColor="cyan" className="flex items-center justify-between p-4 group cursor-pointer hover:bg-white/5 transition-colors">
                            <div className="flex items-center gap-4 w-full overflow-hidden">
                                <div className={`w-12 h-12 rounded-full flex items-center justify-center font-bold text-xl border-2 flex-shrink-0 ${report.grade === 'A' ? 'border-green-500 text-green-400 bg-green-500/10' :
                                    report.grade === 'B' ? 'border-yellow-500 text-yellow-400 bg-yellow-500/10' :
                                        report.grade === 'C' ? 'border-orange-500 text-orange-400 bg-orange-500/10' :
                                            'border-red-500 text-red-400 bg-red-500/10'
                                    }`}>
                                    {report.grade}
                                </div>
                                <div className="min-w-0 flex-1">
                                    <h3 className="font-mono text-lg text-white group-hover:text-cyan-400 transition-colors truncate">
                                        {report.package || report.filename}
                                    </h3>
                                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400 font-mono mt-1">
                                        <span className="flex items-center gap-1"><Clock size={12} /> {new Date(report.timestamp).toLocaleDateString()}</span>
                                        <span className="flex items-center gap-1"><Shield size={12} /> Score: {report.score}</span>
                                        {report.filename && <span className="flex items-center gap-1 truncate max-w-[200px]"><FileText size={12} /> {report.filename}</span>}
                                    </div>
                                </div>
                            </div>
                            <ChevronRight className="text-gray-600 group-hover:text-cyan-400 transition-colors flex-shrink-0 ml-4" />
                        </NeonCard>
                    </Link>
                ))}
            </div>
        </div>
    )
}
