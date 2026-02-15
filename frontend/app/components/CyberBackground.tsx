'use client'

import { useRef, useEffect } from "react"

export default function CyberBackground() {
    const canvasRef = useRef<HTMLCanvasElement>(null)

    useEffect(() => {
        const canvas = canvasRef.current
        if (!canvas) return
        const ctx = canvas.getContext("2d")
        if (!ctx) return

        let width = (canvas.width = window.innerWidth)
        let height = (canvas.height = window.innerHeight)

        const COLORS = [
            { r: 0, g: 255, b: 157 },   // green
            { r: 124, g: 92, b: 252 },   // purple
            { r: 34, g: 211, b: 238 },   // cyan
        ]

        class Particle {
            x: number
            y: number
            vx: number
            vy: number
            size: number
            color: typeof COLORS[0]

            constructor() {
                this.x = Math.random() * width
                this.y = Math.random() * height
                this.vx = (Math.random() - 0.5) * 0.4
                this.vy = (Math.random() - 0.5) * 0.4
                this.size = Math.random() * 1.8 + 0.2
                this.color = COLORS[Math.floor(Math.random() * COLORS.length)]
            }

            update() {
                this.x += this.vx
                this.y += this.vy
                if (this.x < 0 || this.x > width) this.vx *= -1
                if (this.y < 0 || this.y > height) this.vy *= -1
            }

            draw() {
                if (!ctx) return
                ctx.beginPath()
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2)
                ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, 0.45)`
                ctx.fill()
            }
        }

        const particles: Particle[] = []
        const particleCount = Math.min(120, Math.floor((width * height) / 18000))

        for (let i = 0; i < particleCount; i++) {
            particles.push(new Particle())
        }

        const animate = () => {
            ctx.clearRect(0, 0, width, height)

            for (let i = 0; i < particles.length; i++) {
                const p1 = particles[i]
                p1.update()
                p1.draw()

                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j]
                    const dx = p1.x - p2.x
                    const dy = p1.y - p2.y
                    const dist = Math.sqrt(dx * dx + dy * dy)

                    if (dist < 120) {
                        const alpha = (1 - dist / 120) * 0.03
                        ctx.strokeStyle = `rgba(${(p1.color.r + p2.color.r) >> 1}, ${(p1.color.g + p2.color.g) >> 1}, ${(p1.color.b + p2.color.b) >> 1}, ${alpha})`
                        ctx.lineWidth = 0.5
                        ctx.beginPath()
                        ctx.moveTo(p1.x, p1.y)
                        ctx.lineTo(p2.x, p2.y)
                        ctx.stroke()
                    }
                }
            }
            requestAnimationFrame(animate)
        }

        animate()

        const handleResize = () => {
            width = canvas.width = window.innerWidth
            height = canvas.height = window.innerHeight
        }

        window.addEventListener("resize", handleResize)
        return () => window.removeEventListener("resize", handleResize)
    }, [])

    return (
        <>
            {/* Gradient orbs */}
            <div className="fixed inset-0 -z-20 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -left-40 w-[500px] h-[500px] rounded-full bg-purple-600/[0.012] blur-[140px]"
                     style={{ animation: 'orb-float-1 20s ease-in-out infinite' }} />
                <div className="absolute top-1/2 -right-32 w-[400px] h-[400px] rounded-full bg-cyan-500/[0.008] blur-[140px]"
                     style={{ animation: 'orb-float-2 25s ease-in-out infinite' }} />
                <div className="absolute -bottom-40 left-1/3 w-[450px] h-[450px] rounded-full bg-emerald-500/[0.008] blur-[140px]"
                     style={{ animation: 'orb-float-3 22s ease-in-out infinite' }} />
            </div>



            {/* Particle canvas */}
            <canvas
                ref={canvasRef}
                className="fixed top-0 left-0 w-full h-full -z-10 pointer-events-none"
            />
        </>
    )
}
