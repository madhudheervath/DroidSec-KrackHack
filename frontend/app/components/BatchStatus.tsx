'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import NeonCard from './NeonCard'
import { Activity, CheckCircle, AlertTriangle } from 'lucide-react'
import { apiUrl } from '../lib/api'

interface BatchResult {
    name: string
    grade?: string
    score?: number | string
    error?: boolean
}

export default function BatchStatus() {
    const [status, setStatus] = useState<BatchResult[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await fetch(apiUrl('/api/batch-status'))
                const data = await res.json()
                if (Array.isArray(data)) {
                    setStatus(data)
                }
            } catch (e) {
                console.error("Batch status fetch error", e)
            } finally {
                setLoading(false)
            }
        }

        fetchStatus()
        const interval = setInterval(fetchStatus, 3000)
        return () => clearInterval(interval)
    }, [])

    if (loading || status.length === 0) return null

    // Calculate progress (assuming 21 total APKs)
    const scanned = status.length
    const total = 21
    const percent = Math.min((scanned / total) * 100, 100)

    return (
        <NeonCard glowColor="cyan" className="mb-8">
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                    <Activity className="text-cyan-400 animate-pulse" />
                    <h3 className="text-lg font-mono font-bold text-cyan-400">BATCH SCAN ACTIVE</h3>
                </div>
                <span className="font-mono text-cyan-400/80">{scanned}/{total} APKs</span>
            </div>

            <div className="w-full bg-gray-900 rounded-full h-2.5 mb-4 border border-cyan-900/50">
                <motion.div
                    className="bg-cyan-500 h-2.5 rounded-full shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                    initial={{ width: 0 }}
                    animate={{ width: `${percent}%` }}
                    transition={{ duration: 0.5 }}
                />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 font-mono text-sm max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                {status.slice().reverse().map((s, idx) => (
                    <div key={idx} className="flex items-center gap-2 bg-black/40 p-2 rounded border border-white/5 hover:border-white/20 transition-colors">
                        {s.error ? (
                            <AlertTriangle size={14} className="text-red-400 flex-shrink-0" />
                        ) : (
                            <CheckCircle size={14} className={
                                s.grade === 'A' ? 'text-green-400' :
                                    s.grade === 'B' ? 'text-yellow-400' : 'text-red-400'
                            } flex-shrink-0 />
                        )}
                        <span className="truncate flex-1 text-gray-300 text-xs" title={s.name}>{s.name}</span>
                        {s.score && (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${s.grade === 'A' ? 'bg-green-500/20 text-green-400' :
                                s.grade === 'B' ? 'bg-yellow-500/20 text-yellow-400' :
                                    'bg-red-500/20 text-red-400'
                                }`}>{s.score}</span>
                        )}
                    </div>
                ))}
            </div>
        </NeonCard>
    )
}
