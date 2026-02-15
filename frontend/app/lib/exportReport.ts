/**
 * DroidSec — Professional Report Export Utilities
 * Supports PDF (jsPDF + autotable), JSON, and CSV export.
 */
import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

/* ────────────── Types (mirrors report page) ────────────── */
interface Finding {
    id: string; name: string; description: string; severity: string
    confidence?: string; evidence?: string; location?: string
    owasp?: string; remediation?: string; count?: number
}
interface Breakdown { critical?: number; high?: number; medium?: number; info?: number }
interface SecurityScore { score: number; grade: string; risk_level: string; summary?: string }
interface Report {
    scan_id: string; package?: string; apk_filename?: string; timestamp?: string
    total_findings?: number; security_score?: SecurityScore
    severity_breakdown?: Breakdown; findings?: Finding[]
    java_files_scanned?: number; smali_files_scanned?: number
    config_files_scanned?: number; dex_file_count?: number
    owasp_breakdown?: Record<string, { name: string; count: number; max_severity: string }>
    metadata?: {
        package?: string; min_sdk?: string; target_sdk?: string
        permissions?: string[]; exported_components?: string[]
    }
}

/* ────────────── Color helpers (light theme for PDF) ────────────── */

/* Severity badge colors — solid for readability on white */
const SEV_COLORS: Record<string, [number, number, number]> = {
    critical: [200, 30, 40],
    high:     [210, 90, 20],
    medium:   [180, 140, 0],
    info:     [40, 110, 180],
}
/* Severity badge background tints */
const SEV_BG: Record<string, [number, number, number]> = {
    critical: [255, 230, 232],
    high:     [255, 240, 225],
    medium:   [255, 248, 220],
    info:     [225, 240, 255],
}

const GRADE_COLORS: Record<string, [number, number, number]> = {
    A: [22, 160, 80],
    B: [40, 130, 200],
    C: [190, 150, 0],
    D: [210, 100, 20],
    F: [200, 35, 45],
}

/* Theme constants */
const ACCENT:  [number, number, number] = [90, 60, 200]     // deep purple
const HEAD_BG: [number, number, number] = [240, 237, 255]   // very light purple
const ROW_ALT: [number, number, number] = [248, 248, 252]   // subtle gray stripe
const TXT:     [number, number, number] = [30, 30, 40]      // near-black body text
const TXT_DIM: [number, number, number] = [100, 100, 115]   // gray secondary text

/* ================================================================== */
/*  PDF Export  (Clean white-background professional report)           */
/* ================================================================== */
export function exportPDF(report: Report) {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
    const pageW = doc.internal.pageSize.getWidth()
    const pageH = doc.internal.pageSize.getHeight()
    const margin = 15
    const contentW = pageW - margin * 2
    let y = 0

    const score = report.security_score || { score: 0, grade: '?', risk_level: 'Unknown', summary: '' }
    const breakdown = report.severity_breakdown || {}
    const findings = report.findings || []
    const meta = report.metadata || {}
    const pkg = report.package || meta.package || 'Unknown'
    const ts = report.timestamp ? new Date(report.timestamp).toLocaleString() : new Date().toLocaleString()

    /* ── Reusable helpers ── */
    const sectionTitle = (title: string) => {
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(13)
        doc.setTextColor(ACCENT[0], ACCENT[1], ACCENT[2])
        doc.text(title, margin, y)
        doc.setDrawColor(ACCENT[0], ACCENT[1], ACCENT[2])
        doc.setLineWidth(0.4)
        doc.line(margin, y + 2, margin + doc.getTextWidth(title), y + 2)
        y += 8
    }

    const tableDefaults = () => ({
        margin: { left: margin, right: margin },
        theme: 'striped' as const,
        styles: {
            fontSize: 9,
            textColor: TXT as [number, number, number],
            cellPadding: 3,
            lineColor: [220, 220, 230] as [number, number, number],
            lineWidth: 0.2,
        },
        headStyles: {
            fillColor: HEAD_BG as [number, number, number],
            textColor: ACCENT as [number, number, number],
            fontStyle: 'bold' as const,
            lineColor: [200, 195, 230] as [number, number, number],
            lineWidth: 0.3,
        },
        alternateRowStyles: { fillColor: ROW_ALT as [number, number, number] },
    })

    /* ═══════════════════════════════════════════════════════════════ */
    /*  PAGE 1 — Cover                                                */
    /* ═══════════════════════════════════════════════════════════════ */

    // Header band
    doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2])
    doc.rect(0, 0, pageW, 50, 'F')

    doc.setFont('helvetica', 'bold')
    doc.setTextColor(255, 255, 255)
    doc.setFontSize(26)
    doc.text('DROIDSEC', margin, 22)
    doc.setFontSize(10)
    doc.setTextColor(220, 215, 255)
    doc.text('APK SECURITY ANALYSIS REPORT', margin, 30)

    // Right-aligned meta
    doc.setFontSize(8)
    doc.setTextColor(210, 205, 255)
    doc.text(ts, pageW - margin, 22, { align: 'right' })
    doc.text(`Report ID: ${report.scan_id || 'N/A'}`, pageW - margin, 28, { align: 'right' })

    // Thin accent line below header
    doc.setFillColor(70, 40, 170)
    doc.rect(0, 50, pageW, 1.2, 'F')

    y = 62

    // ── Score Card ──
    const gradeColor = GRADE_COLORS[score.grade] || [120, 120, 120]
    doc.setFillColor(250, 249, 255)
    doc.roundedRect(margin, y, contentW, 36, 3, 3, 'F')
    doc.setDrawColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.setLineWidth(0.7)
    doc.roundedRect(margin, y, contentW, 36, 3, 3, 'S')

    // Grade circle
    const cx = margin + 22, cy = y + 18
    doc.setFillColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.circle(cx, cy, 13, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(20)
    doc.setTextColor(255, 255, 255)
    doc.text(score.grade, cx, cy + 3, { align: 'center' })

    // Score info
    doc.setTextColor(TXT[0], TXT[1], TXT[2])
    doc.setFontSize(18)
    doc.text(`${score.score}/100`, margin + 44, y + 14)
    doc.setFontSize(10)
    doc.setTextColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.text(score.risk_level || 'Unknown Risk', margin + 44, y + 22)
    doc.setFontSize(8)
    doc.setTextColor(TXT_DIM[0], TXT_DIM[1], TXT_DIM[2])
    doc.text(`${report.total_findings || findings.length} findings identified`, margin + 44, y + 29)

    y += 46

    // ── Application Details ──
    sectionTitle('APPLICATION DETAILS')

    autoTable(doc, {
        ...tableDefaults(),
        startY: y,
        body: [
            ['Package', pkg],
            ['APK File', report.apk_filename || 'N/A'],
            ['Min SDK', meta.min_sdk || 'N/A'],
            ['Target SDK', meta.target_sdk || 'N/A'],
            ['Permissions', String(meta.permissions?.length || 0)],
            ['Exported Components', String(meta.exported_components?.length || 0)],
            ['Scan Date', ts],
        ],
        columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 45, textColor: ACCENT as [number, number, number] },
            1: { cellWidth: contentW - 45 },
        },
    })

    y = (doc as any).lastAutoTable.finalY + 12

    // ── Severity Breakdown ──
    sectionTitle('SEVERITY BREAKDOWN')

    autoTable(doc, {
        ...tableDefaults(),
        startY: y,
        head: [['Severity', 'Count', 'Impact']],
        body: [
            ['Critical', String(breakdown.critical || 0), 'Immediate exploitation risk'],
            ['High', String(breakdown.high || 0), 'Significant security impact'],
            ['Medium', String(breakdown.medium || 0), 'Moderate risk, should fix'],
            ['Info', String(breakdown.info || 0), 'Best practice recommendation'],
        ],
        didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 0) {
                const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                const c = SEV_COLORS[sev]; const bg = SEV_BG[sev]
                if (c) { data.cell.styles.textColor = c; data.cell.styles.fontStyle = 'bold' }
                if (bg) data.cell.styles.fillColor = bg
            }
        },
    })

    y = (doc as any).lastAutoTable.finalY + 12

    // ── OWASP Coverage ──
    const owaspData = report.owasp_breakdown
    if (owaspData && Object.keys(owaspData).length > 0) {
        if (y > pageH - 60) { doc.addPage(); y = margin }
        sectionTitle('OWASP MOBILE TOP 10 COVERAGE')

        autoTable(doc, {
            ...tableDefaults(),
            startY: y,
            head: [['Code', 'Category', 'Findings', 'Max Severity']],
            body: Object.entries(owaspData).map(([code, cat]) => [
                code, cat.name, String(cat.count), cat.max_severity || '-',
            ]),
            styles: { ...tableDefaults().styles, fontSize: 8.5, cellPadding: 2.8 },
            columnStyles: { 0: { cellWidth: 18, fontStyle: 'bold', textColor: ACCENT as [number, number, number] } },
            didParseCell: (data: any) => {
                if (data.section === 'body' && data.column.index === 3) {
                    const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                    const c = SEV_COLORS[sev]
                    if (c) { data.cell.styles.textColor = c; data.cell.styles.fontStyle = 'bold' }
                }
            },
        })

        y = (doc as any).lastAutoTable.finalY + 12
    }

    /* ═══════════════════════════════════════════════════════════════ */
    /*  FINDINGS DETAIL PAGES                                         */
    /* ═══════════════════════════════════════════════════════════════ */
    if (findings.length > 0) {
        doc.addPage()
        y = margin

        // Mini header bar
        doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2])
        doc.rect(0, 0, pageW, 18, 'F')
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(13)
        doc.setTextColor(255, 255, 255)
        doc.text('DETAILED FINDINGS', margin, 12)
        y = 24

        autoTable(doc, {
            ...tableDefaults(),
            startY: y,
            head: [['#', 'Severity', 'Finding', 'OWASP', 'Location', 'Description']],
            body: findings.map((f, i) => [
                String(i + 1),
                f.severity?.toUpperCase() || '?',
                f.name || 'Unknown',
                f.owasp || '-',
                f.location || '-',
                (f.description || '').substring(0, 80) + ((f.description || '').length > 80 ? '...' : ''),
            ]),
            styles: { ...tableDefaults().styles, fontSize: 7.5, cellPadding: 2.2, overflow: 'linebreak' as const },
            headStyles: { ...tableDefaults().headStyles, fontSize: 8 },
            columnStyles: {
                0: { cellWidth: 8, halign: 'center' as const },
                1: { cellWidth: 16 },
                2: { cellWidth: 38 },
                3: { cellWidth: 16 },
                4: { cellWidth: 32 },
                5: { cellWidth: contentW - 110 },
            },
            didParseCell: (data: any) => {
                if (data.section === 'body' && data.column.index === 1) {
                    const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                    const c = SEV_COLORS[sev]
                    if (c) { data.cell.styles.textColor = c; data.cell.styles.fontStyle = 'bold' }
                }
            },
        })

        y = (doc as any).lastAutoTable.finalY + 12

        // ── High-priority findings with evidence & fix ──
        const importantFindings = findings.filter(f =>
            ['critical', 'high'].includes((f.severity || '').toLowerCase())
        )

        if (importantFindings.length > 0) {
            if (y > pageH - 40) { doc.addPage(); y = margin }

            doc.setFont('helvetica', 'bold')
            doc.setFontSize(12)
            doc.setTextColor(SEV_COLORS.critical[0], SEV_COLORS.critical[1], SEV_COLORS.critical[2])
            doc.text('HIGH-PRIORITY FINDINGS — DETAIL', margin, y)
            y += 8

            for (const f of importantFindings) {
                if (y > pageH - 50) { doc.addPage(); y = margin }

                const sevColor = SEV_COLORS[(f.severity || '').toLowerCase()] || [80, 80, 80]
                const sevBg = SEV_BG[(f.severity || '').toLowerCase()] || [245, 245, 245]

                // Title bar
                doc.setFillColor(sevBg[0], sevBg[1], sevBg[2])
                doc.roundedRect(margin, y, contentW, 8, 1.5, 1.5, 'F')
                doc.setDrawColor(sevColor[0], sevColor[1], sevColor[2])
                doc.setLineWidth(0.4)
                doc.roundedRect(margin, y, contentW, 8, 1.5, 1.5, 'S')
                doc.setFont('helvetica', 'bold')
                doc.setFontSize(9)
                doc.setTextColor(sevColor[0], sevColor[1], sevColor[2])
                doc.text(`[${(f.severity || '?').toUpperCase()}]  ${f.name}`, margin + 3, y + 5.5)

                if (f.owasp) {
                    doc.setFontSize(7)
                    doc.setTextColor(ACCENT[0], ACCENT[1], ACCENT[2])
                    doc.text(f.owasp, pageW - margin - 3, y + 5.5, { align: 'right' })
                }
                y += 12

                // Location
                if (f.location) {
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(7.5)
                    doc.setTextColor(TXT_DIM[0], TXT_DIM[1], TXT_DIM[2])
                    doc.text(`Location: ${f.location}`, margin + 2, y)
                    y += 5
                }

                // Description
                if (f.description) {
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(8)
                    doc.setTextColor(TXT[0], TXT[1], TXT[2])
                    const lines = doc.splitTextToSize(f.description, contentW - 6)
                    doc.text(lines, margin + 2, y)
                    y += lines.length * 4 + 3
                }

                // Evidence box
                if (f.evidence) {
                    doc.setFillColor(245, 245, 250)
                    const evLines = doc.splitTextToSize(`Evidence: ${f.evidence}`, contentW - 10)
                    const evH = evLines.length * 3.5 + 5
                    doc.roundedRect(margin + 2, y, contentW - 4, evH, 1, 1, 'F')
                    doc.setDrawColor(200, 195, 220)
                    doc.setLineWidth(0.2)
                    doc.roundedRect(margin + 2, y, contentW - 4, evH, 1, 1, 'S')
                    doc.setFont('courier', 'normal')
                    doc.setFontSize(6.5)
                    doc.setTextColor(80, 60, 150)
                    doc.text(evLines, margin + 5, y + 4)
                    y += evH + 3
                }

                // Remediation box
                if (f.remediation) {
                    doc.setFillColor(235, 250, 240)
                    const remLines = doc.splitTextToSize(`Fix: ${f.remediation}`, contentW - 10)
                    const remH = remLines.length * 3.8 + 5
                    doc.roundedRect(margin + 2, y, contentW - 4, remH, 1, 1, 'F')
                    doc.setDrawColor(160, 220, 180)
                    doc.setLineWidth(0.2)
                    doc.roundedRect(margin + 2, y, contentW - 4, remH, 1, 1, 'S')
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(7.5)
                    doc.setTextColor(20, 120, 60)
                    doc.text(remLines, margin + 5, y + 4)
                    y += remH + 4
                }

                y += 4
            }
        }
    }

    // ── Footer on every page ──
    const totalPages = (doc as any).internal.getNumberOfPages()
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setDrawColor(200, 200, 210)
        doc.setLineWidth(0.3)
        doc.line(margin, pageH - 14, pageW - margin, pageH - 14)
        doc.setFontSize(7)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(TXT_DIM[0], TXT_DIM[1], TXT_DIM[2])
        doc.text('Generated by DroidSec — APK Security Analyzer', margin, pageH - 8)
        doc.text(`Page ${i} of ${totalPages}`, pageW - margin, pageH - 8, { align: 'right' })
    }

    doc.save(`DroidSec-Report-${pkg.replace(/\./g, '_')}.pdf`)
}


/* ================================================================== */
/*  JSON Export                                                        */
/* ================================================================== */
export function exportJSON(report: Report) {
    const pkg = report.package || report.metadata?.package || 'unknown'
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `DroidSec-Report-${pkg.replace(/\./g, '_')}.json`
    a.click()
    URL.revokeObjectURL(url)
}


/* ================================================================== */
/*  CSV Export                                                         */
/* ================================================================== */
export function exportCSV(report: Report) {
    const findings = report.findings || []
    const pkg = report.package || report.metadata?.package || 'unknown'

    const headers = ['#', 'Severity', 'Name', 'OWASP', 'Location', 'Description', 'Evidence', 'Remediation']
    const rows = findings.map((f, i) => [
        String(i + 1),
        f.severity || '',
        f.name || '',
        f.owasp || '',
        f.location || '',
        (f.description || '').replace(/"/g, '""'),
        (f.evidence || '').replace(/"/g, '""'),
        (f.remediation || '').replace(/"/g, '""'),
    ])

    const csvContent = [
        `# DroidSec Security Report — ${pkg}`,
        `# Score: ${report.security_score?.score || 0}/100 (Grade ${report.security_score?.grade || '?'})`,
        `# Scan Date: ${report.timestamp || 'N/A'}`,
        `# Total Findings: ${report.total_findings || findings.length}`,
        '',
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `DroidSec-Report-${pkg.replace(/\./g, '_')}.csv`
    a.click()
    URL.revokeObjectURL(url)
}
