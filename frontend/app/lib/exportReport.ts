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

/* ────────────── Color helpers ────────────── */
const SEV_COLORS: Record<string, [number, number, number]> = {
    critical: [255, 71, 87],
    high:     [255, 140, 66],
    medium:   [255, 209, 102],
    info:     [110, 198, 255],
}

const GRADE_COLORS: Record<string, [number, number, number]> = {
    A: [46, 213, 115],
    B: [110, 198, 255],
    C: [255, 209, 102],
    D: [255, 140, 66],
    F: [255, 71, 87],
}

/* ================================================================== */
/*  PDF Export                                                         */
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

    /* ── Page 1: Cover ── */
    // Dark header band
    doc.setFillColor(8, 8, 14)
    doc.rect(0, 0, pageW, 65, 'F')

    // Accent line
    doc.setFillColor(139, 108, 255)
    doc.rect(0, 65, pageW, 1.5, 'F')

    // Title
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(255, 255, 255)
    doc.setFontSize(28)
    doc.text('DROIDSEC', margin, 28)
    doc.setFontSize(10)
    doc.setTextColor(160, 160, 200)
    doc.text('APK SECURITY ANALYSIS REPORT', margin, 36)

    // Timestamp right-aligned
    doc.setFontSize(8)
    doc.setTextColor(120, 120, 160)
    const ts = report.timestamp ? new Date(report.timestamp).toLocaleString() : new Date().toLocaleString()
    doc.text(ts, pageW - margin, 28, { align: 'right' })
    doc.text(`Report ID: ${report.scan_id || 'N/A'}`, pageW - margin, 34, { align: 'right' })

    y = 78

    // Score Card
    const gradeColor = GRADE_COLORS[score.grade] || [160, 160, 160]
    doc.setFillColor(12, 12, 18)
    doc.roundedRect(margin, y, contentW, 40, 3, 3, 'F')
    doc.setDrawColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.setLineWidth(0.5)
    doc.roundedRect(margin, y, contentW, 40, 3, 3, 'S')

    // Grade circle
    const circleX = margin + 22
    const circleY = y + 20
    doc.setFillColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.circle(circleX, circleY, 14, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(22)
    doc.setTextColor(0, 0, 0)
    doc.text(score.grade, circleX, circleY + 3, { align: 'center' })

    // Score text
    doc.setTextColor(240, 240, 248)
    doc.setFontSize(20)
    doc.text(`${score.score}/100`, margin + 45, y + 16)
    doc.setFontSize(10)
    doc.setTextColor(gradeColor[0], gradeColor[1], gradeColor[2])
    doc.text(score.risk_level || 'Unknown Risk', margin + 45, y + 24)
    doc.setFontSize(8)
    doc.setTextColor(160, 160, 180)
    doc.text(`${report.total_findings || findings.length} findings identified`, margin + 45, y + 32)

    y += 50

    // App Info table
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(12)
    doc.setTextColor(139, 108, 255)
    doc.text('APPLICATION DETAILS', margin, y)
    y += 6

    autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        theme: 'plain',
        styles: { fontSize: 9, textColor: [200, 200, 220], cellPadding: 3 },
        headStyles: { fillColor: [15, 15, 24], textColor: [139, 108, 255], fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [10, 10, 16] },
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
            0: { fontStyle: 'bold', cellWidth: 45, textColor: [160, 160, 200] },
            1: { cellWidth: contentW - 45 },
        },
    })

    y = (doc as any).lastAutoTable.finalY + 10

    // Severity Breakdown
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(12)
    doc.setTextColor(139, 108, 255)
    doc.text('SEVERITY BREAKDOWN', margin, y)
    y += 6

    const sevData = [
        ['Critical', String(breakdown.critical || 0), 'Immediate exploitation risk'],
        ['High', String(breakdown.high || 0), 'Significant security impact'],
        ['Medium', String(breakdown.medium || 0), 'Moderate risk, should fix'],
        ['Info', String(breakdown.info || 0), 'Best practice recommendation'],
    ]

    autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [['Severity', 'Count', 'Impact']],
        body: sevData,
        theme: 'plain',
        styles: { fontSize: 9, textColor: [200, 200, 220], cellPadding: 3 },
        headStyles: { fillColor: [15, 15, 24], textColor: [139, 108, 255], fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [10, 10, 16] },
        didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 0) {
                const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                const color = SEV_COLORS[sev]
                if (color) data.cell.styles.textColor = color
            }
        },
    })

    y = (doc as any).lastAutoTable.finalY + 10

    // OWASP Coverage
    const owaspData = report.owasp_breakdown
    if (owaspData && Object.keys(owaspData).length > 0) {
        if (y > pageH - 60) { doc.addPage(); y = margin }
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(12)
        doc.setTextColor(139, 108, 255)
        doc.text('OWASP MOBILE TOP 10 COVERAGE', margin, y)
        y += 6

        const owaspRows = Object.entries(owaspData).map(([code, cat]) => [
            code,
            cat.name,
            String(cat.count),
            cat.max_severity || '-',
        ])

        autoTable(doc, {
            startY: y,
            margin: { left: margin, right: margin },
            head: [['Code', 'Category', 'Findings', 'Max Severity']],
            body: owaspRows,
            theme: 'plain',
            styles: { fontSize: 8, textColor: [200, 200, 220], cellPadding: 2.5 },
            headStyles: { fillColor: [15, 15, 24], textColor: [139, 108, 255], fontStyle: 'bold' },
            alternateRowStyles: { fillColor: [10, 10, 16] },
            columnStyles: { 0: { cellWidth: 18, fontStyle: 'bold' } },
            didParseCell: (data: any) => {
                if (data.section === 'body' && data.column.index === 3) {
                    const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                    const color = SEV_COLORS[sev]
                    if (color) data.cell.styles.textColor = color
                }
            },
        })

        y = (doc as any).lastAutoTable.finalY + 10
    }

    /* ── Findings Detail Pages ── */
    if (findings.length > 0) {
        doc.addPage()
        y = margin

        doc.setFillColor(8, 8, 14)
        doc.rect(0, 0, pageW, 20, 'F')
        doc.setFillColor(139, 108, 255)
        doc.rect(0, 20, pageW, 0.8, 'F')

        doc.setFont('helvetica', 'bold')
        doc.setFontSize(14)
        doc.setTextColor(255, 255, 255)
        doc.text('DETAILED FINDINGS', margin, 14)
        y = 28

        const findingRows = findings.map((f, i) => [
            String(i + 1),
            f.severity?.toUpperCase() || '?',
            f.name || 'Unknown',
            f.owasp || '-',
            f.location || '-',
            (f.description || '').substring(0, 80) + ((f.description || '').length > 80 ? '...' : ''),
        ])

        autoTable(doc, {
            startY: y,
            margin: { left: margin, right: margin },
            head: [['#', 'Severity', 'Finding', 'OWASP', 'Location', 'Description']],
            body: findingRows,
            theme: 'plain',
            styles: { fontSize: 7, textColor: [200, 200, 220], cellPadding: 2, overflow: 'linebreak' },
            headStyles: { fillColor: [15, 15, 24], textColor: [139, 108, 255], fontStyle: 'bold', fontSize: 7.5 },
            alternateRowStyles: { fillColor: [10, 10, 16] },
            columnStyles: {
                0: { cellWidth: 8, halign: 'center' },
                1: { cellWidth: 16 },
                2: { cellWidth: 38 },
                3: { cellWidth: 16 },
                4: { cellWidth: 32 },
                5: { cellWidth: contentW - 110 },
            },
            didParseCell: (data: any) => {
                if (data.section === 'body' && data.column.index === 1) {
                    const sev = data.cell.raw?.toString()?.toLowerCase() || ''
                    const color = SEV_COLORS[sev]
                    if (color) data.cell.styles.textColor = color
                    data.cell.styles.fontStyle = 'bold'
                }
            },
        })

        y = (doc as any).lastAutoTable.finalY + 12

        // Detailed evidence & remediation for critical/high findings
        const importantFindings = findings.filter(f =>
            ['critical', 'high'].includes((f.severity || '').toLowerCase())
        )

        if (importantFindings.length > 0) {
            if (y > pageH - 40) { doc.addPage(); y = margin }

            doc.setFont('helvetica', 'bold')
            doc.setFontSize(12)
            doc.setTextColor(255, 82, 82)
            doc.text('HIGH-PRIORITY FINDINGS — DETAIL', margin, y)
            y += 8

            for (const f of importantFindings) {
                if (y > pageH - 50) { doc.addPage(); y = margin }

                const sevColor = SEV_COLORS[(f.severity || '').toLowerCase()] || [200, 200, 200]

                // Finding header
                doc.setFillColor(12, 12, 18)
                doc.roundedRect(margin, y, contentW, 8, 1.5, 1.5, 'F')
                doc.setDrawColor(sevColor[0], sevColor[1], sevColor[2])
                doc.setLineWidth(0.3)
                doc.roundedRect(margin, y, contentW, 8, 1.5, 1.5, 'S')
                doc.setFont('helvetica', 'bold')
                doc.setFontSize(9)
                doc.setTextColor(sevColor[0], sevColor[1], sevColor[2])
                doc.text(`[${(f.severity || '?').toUpperCase()}] ${f.name}`, margin + 3, y + 5.5)

                if (f.owasp) {
                    doc.setFontSize(7)
                    doc.setTextColor(139, 108, 255)
                    doc.text(f.owasp, pageW - margin - 3, y + 5.5, { align: 'right' })
                }
                y += 12

                // Location
                if (f.location) {
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(7.5)
                    doc.setTextColor(120, 120, 170)
                    doc.text(`Location: ${f.location}`, margin + 2, y)
                    y += 5
                }

                // Description
                if (f.description) {
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(8)
                    doc.setTextColor(200, 200, 220)
                    const descLines = doc.splitTextToSize(f.description, contentW - 6)
                    doc.text(descLines, margin + 2, y)
                    y += descLines.length * 4 + 3
                }

                // Evidence
                if (f.evidence) {
                    doc.setFillColor(6, 6, 10)
                    const evLines = doc.splitTextToSize(`Evidence: ${f.evidence}`, contentW - 10)
                    const evH = evLines.length * 3.5 + 4
                    doc.roundedRect(margin + 2, y, contentW - 4, evH, 1, 1, 'F')
                    doc.setFont('courier', 'normal')
                    doc.setFontSize(6.5)
                    doc.setTextColor(139, 108, 255)
                    doc.text(evLines, margin + 5, y + 3.5)
                    y += evH + 3
                }

                // Remediation
                if (f.remediation) {
                    doc.setFont('helvetica', 'normal')
                    doc.setFontSize(7.5)
                    doc.setTextColor(46, 213, 115)
                    const remLines = doc.splitTextToSize(`Fix: ${f.remediation}`, contentW - 6)
                    doc.text(remLines, margin + 2, y)
                    y += remLines.length * 3.8 + 6
                }

                y += 4
            }
        }
    }

    // Footer on every page
    const totalPages = (doc as any).internal.getNumberOfPages()
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setFillColor(8, 8, 14)
        doc.rect(0, pageH - 12, pageW, 12, 'F')
        doc.setFontSize(7)
        doc.setTextColor(100, 100, 140)
        doc.text('Generated by DroidSec — APK Security Analyzer', margin, pageH - 5)
        doc.text(`Page ${i} of ${totalPages}`, pageW - margin, pageH - 5, { align: 'right' })
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
