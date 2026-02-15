'use client'

import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, FileCode, AlertCircle, Loader2 } from 'lucide-react'
import NeonCard from './NeonCard'
import { useRouter } from 'next/navigation'
import { apiUrl } from '../lib/api'

export default function UploadZone() {
    const [isDragging, setIsDragging] = useState(false)
    const [file, setFile] = useState<File | null>(null)
    const [uploading, setUploading] = useState(false)
    const [scanStatusText, setScanStatusText] = useState('Decompiling bytecode & scanning heuristics')
    const [error, setError] = useState<string | null>(null)
    const router = useRouter()

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setIsDragging(true)
        } else if (e.type === 'dragleave') {
            setIsDragging(false)
        }
    }, [])

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(false)

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            validateAndSetFile(e.dataTransfer.files[0])
        }
    }, [])

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            validateAndSetFile(e.target.files[0])
        }
    }

    const validateAndSetFile = (f: File) => {
        if (!f.name.endsWith('.apk')) {
            setError("Only .apk files are supported")
            return
        }
        setError(null)
        setFile(f)
    }

    const handleScan = async () => {
        if (!file) return
        setUploading(true)
        setError(null)
        setScanStatusText('Uploading APK payload...')

        const formData = new FormData()
        formData.append('file', file)

        try {
            const res = await fetch(apiUrl('/api/scan'), {
                method: 'POST',
                body: formData,
            })

            if (!res.ok) {
                let message = "Scan failed"
                try {
                    const errData = await res.json()
                    message = errData?.detail || message
                } catch {
                    try {
                        message = await res.text()
                    } catch {
                        // keep default
                    }
                }
                throw new Error(message)
            }

            const data = await res.json()
            const scanId = data.scan_id || data.metadata?.scan_id

            if (scanId) {
                // Backward compatibility: old backend returned full report in one call.
                if (data.security_score) {
                    router.push(`/report/${scanId}`)
                    return
                }

                setScanStatusText('Scan queued. Waiting for decompiler...')
                const startedAt = Date.now()
                const timeoutMs = 20 * 60 * 1000

                while (Date.now() - startedAt < timeoutMs) {
                    const statusRes = await fetch(apiUrl(`/api/scan/${scanId}/status`), { cache: 'no-store' })
                    if (!statusRes.ok) {
                        const statusText = await statusRes.text()
                        throw new Error(statusText || 'Failed to check scan status')
                    }
                    const statusData = await statusRes.json()
                    const status = String(statusData?.status || '').toLowerCase()

                    if (status === 'completed') {
                        router.push(`/report/${scanId}`)
                        return
                    }
                    if (status === 'failed') {
                        throw new Error(statusData?.error || 'Scan failed')
                    }

                    if (status === 'queued') {
                        setScanStatusText('Scan queued. Waiting for worker slot...')
                    } else {
                        setScanStatusText('Decompiling and scanning...')
                    }

                    await new Promise((resolve) => setTimeout(resolve, 2500))
                }

                throw new Error('Scan timed out. Please retry.')
            } else {
                setError("Invalid server response")
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : "Upload failed. Is the backend running?"
            setError(message)
        } finally {
            setUploading(false)
            setScanStatusText('Decompiling bytecode & scanning heuristics')
        }
    }

    return (
        <NeonCard glowColor={error ? 'red' : 'green'} className="w-full max-w-2xl mx-auto text-center relative overflow-hidden group">
            <div
                className={`border-2 border-dashed rounded-lg p-12 transition-all duration-300 ${isDragging ? 'border-green-400 bg-green-400/10 scale-[1.02]' : 'border-gray-600 hover:border-gray-400'
                    }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
            >
                <AnimatePresence mode='wait'>
                    {uploading ? (
                        <motion.div
                            key="scanning"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex flex-col items-center gap-4"
                        >
                            <Loader2 size={48} className="text-green-400 animate-spin" />
                            <h3 className="text-xl font-mono text-green-400 animate-pulse">ANALYZING APK STRUCTURE...</h3>
                            <p className="text-gray-400 text-sm">{scanStatusText}</p>
                        </motion.div>
                    ) : file ? (
                        <motion.div
                            key="file"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="flex flex-col items-center gap-4"
                        >
                            <div className="bg-green-500/20 p-4 rounded-full">
                                <FileCode size={40} className="text-green-400" />
                            </div>
                            <h3 className="text-xl font-mono text-white max-w-full truncate">{file.name}</h3>
                            <p className="text-gray-400 text-sm">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>

                            <div className="flex gap-4 mt-4">
                                <button
                                    onClick={() => setFile(null)}
                                    className="px-6 py-2 rounded border border-red-500/50 text-red-400 hover:bg-red-500/10 font-mono transition-colors"
                                >
                                    CANCEL
                                </button>
                                <button
                                    onClick={handleScan}
                                    className="px-8 py-2 rounded bg-green-500 hover:bg-green-400 text-black font-bold font-mono shadow-[0_0_20px_rgba(34,197,94,0.4)] transition-all hover:scale-105"
                                >
                                    INITIATE SCAN
                                </button>
                            </div>
                        </motion.div>
                    ) : (
                        <div className="relative">
                            <motion.div
                                key="upload"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="flex flex-col items-center gap-4 pointer-events-none"
                            >
                                <div className="bg-gray-800 p-4 rounded-full group-hover:bg-gray-700 transition-colors">
                                    <Upload size={40} className="text-gray-400 group-hover:text-green-400 transition-colors" />
                                </div>
                                <h3 className="text-xl font-mono text-gray-200">DROP APK TARGET HERE</h3>
                                <p className="text-gray-400 text-sm">or click to browse filesystem</p>
                            </motion.div>
                            <input
                                type="file"
                                accept=".apk"
                                onChange={handleFileSelect}
                                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                            />
                        </div>
                    )}
                </AnimatePresence>
            </div>

            {error && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-md flex items-center justify-center gap-2 text-red-400"
                >
                    <AlertCircle size={20} />
                    <span className="font-mono">{error}</span>
                </motion.div>
            )}
        </NeonCard>
    )
}
