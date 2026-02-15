'use client'

import CyberBackground from './components/CyberBackground'
import UploadZone from './components/UploadZone'
import RecentScans from './components/RecentScans'

export default function Home() {
  return (
    <main className="min-h-screen relative text-white selection:bg-green-500/30 overflow-hidden">
      <CyberBackground />

      <div className="relative z-10 container mx-auto px-4 py-12 flex flex-col items-center">
        {/* Header */}
        <header className="mb-16 text-center w-full">
          <div className="inline-block relative group">
            <h1 className="text-6xl md:text-8xl font-black tracking-tighter mb-4 glitch-text select-none cursor-default" data-text="DROIDSEC">
              DROIDSEC
            </h1>
            <div className="absolute -top-4 -right-8 px-2 py-1 bg-green-500 text-black text-xs font-bold font-mono transform rotate-12 shadow-[0_0_10px_rgba(34,197,94,0.6)]">
              v1.0.0
            </div>
            <div className="absolute -bottom-2 w-full h-1 bg-gradient-to-r from-transparent via-green-500 to-transparent opacity-50 group-hover:opacity-100 transition-opacity" />
          </div>
          <p className="text-xl md:text-2xl text-gray-300 font-mono max-w-2xl mx-auto mt-4 tracking-wide">
            ADVANCED ANDROID SECURITY ANALYSIS PLATFORM
          </p>
        </header>


        {/* Upload Zone */}
        <UploadZone />

        {/* Recent Scans */}
        <RecentScans />

        {/* Footer */}
        <footer className="mt-24 text-center text-gray-500 font-mono text-xs md:text-sm">
          <p className="tracking-widest mb-2">SYSTEM STATUS: <span className="text-green-400 animate-pulse">ONLINE</span> • SECURE CONNECTION ESTABLISHED</p>
          <p className="opacity-60">POWERED BY GROQ AI & JADX DECOMPILER</p>
        </footer>
      </div>

      <style jsx global>{`
        .glitch-text {
          position: relative;
          color: white;
        }
        .glitch-text::before,
        .glitch-text::after {
          content: attr(data-text);
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          opacity: 0.8;
        }
        .glitch-text::before {
          left: 2px;
          text-shadow: -1px 0 #ff00c1;
          clip: rect(44px, 450px, 56px, 0);
          animation: glitch-anim 5s infinite linear alternate-reverse;
        }
        .glitch-text::after {
          left: -2px;
          text-shadow: -1px 0 #00fff9;
          clip: rect(44px, 450px, 56px, 0);
          animation: glitch-anim2 5s infinite linear alternate-reverse;
        }
        @keyframes glitch-anim {
          0% { clip: rect(11px, 9999px, 81px, 0); }
          20% { clip: rect(87px, 9999px, 96px, 0); }
          40% { clip: rect(10px, 9999px, 5px, 0); }
          60% { clip: rect(21px, 9999px, 63px, 0); }
          80% { clip: rect(82px, 9999px, 6px, 0); }
          100% { clip: rect(2px, 9999px, 20px, 0); }
        }
        @keyframes glitch-anim2 {
          0% { clip: rect(66px, 9999px, 49px, 0); }
          20% { clip: rect(31px, 9999px, 26px, 0); }
          40% { clip: rect(78px, 9999px, 25px, 0); }
          60% { clip: rect(9px, 9999px, 83px, 0); }
          80% { clip: rect(25px, 9999px, 32px, 0); }
          100% { clip: rect(54px, 9999px, 93px, 0); }
        }
        
        /* Custom Scrollbar */
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(0, 0, 0, 0.2);
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(6, 182, 212, 0.3);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(6, 182, 212, 0.5);
        }
      `}</style>
    </main>
  )
}
