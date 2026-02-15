'use client'

import { useState, useEffect } from 'react'
import NeonCard from './NeonCard'
import { Shield, Clock, FileText, ChevronRight } from 'lucide-react'
import Link from 'next/link'
import { apiUrl } from '../lib/api'

interface RecentReport {
    scan_id: string
    package?: string
    filename?: string
    timestamp: string
    score?: number | string
    grade?: string
}

export default function RecentScans() {
    const [reports, setReports] = useState<RecentReport[]>([])

    useEffect(() => {
        fetch(apiUrl('/api/reports'))
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data)) setReports(data.slice(0, 5))
            })
            .catch(err => console.error(err))
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
