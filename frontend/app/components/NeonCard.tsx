import { twMerge } from 'tailwind-merge'
import { ReactNode } from 'react'

interface NeonCardProps {
    children: ReactNode
    className?: string
    glowColor?: 'green' | 'cyan' | 'red' | 'yellow' | 'orange' | 'blue' | 'purple'
}

export default function NeonCard({ children, className, glowColor = 'green' }: NeonCardProps) {
    const glowMap = {
        green: 'hover:shadow-[0_0_20px_rgba(34,197,94,0.3)] hover:border-green-500/50 border-green-500/20 bg-black/60 shadow-[0_0_10px_rgba(34,197,94,0.1)]',
        cyan: 'hover:shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:border-cyan-500/50 border-cyan-500/20 bg-black/60 shadow-[0_0_10px_rgba(6,182,212,0.1)]',
        red: 'hover:shadow-[0_0_20px_rgba(239,68,68,0.3)] hover:border-red-500/50 border-red-500/20 bg-black/60 shadow-[0_0_10px_rgba(239,68,68,0.1)]',
        yellow: 'hover:shadow-[0_0_20px_rgba(234,179,8,0.3)] hover:border-yellow-500/50 border-yellow-500/20 bg-black/60 shadow-[0_0_10px_rgba(234,179,8,0.1)]',
        orange: 'hover:shadow-[0_0_20px_rgba(249,115,22,0.3)] hover:border-orange-500/50 border-orange-500/20 bg-black/60 shadow-[0_0_10px_rgba(249,115,22,0.1)]',
        blue: 'hover:shadow-[0_0_20px_rgba(59,130,246,0.3)] hover:border-blue-500/50 border-blue-500/20 bg-black/60 shadow-[0_0_10px_rgba(59,130,246,0.1)]',
        purple: 'hover:shadow-[0_0_20px_rgba(168,85,247,0.3)] hover:border-purple-500/50 border-purple-500/20 bg-black/60 shadow-[0_0_10px_rgba(168,85,247,0.1)]',
    }

    return (
        <div className={twMerge(
            "relative backdrop-blur-md border rounded-xl p-6 transition-all duration-300",
            glowMap[glowColor],
            className
        )}>
            {children}
        </div>
    )
}
