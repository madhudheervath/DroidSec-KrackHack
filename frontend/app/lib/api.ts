export function getApiBaseUrl(): string {
    const configured = (process.env.NEXT_PUBLIC_BACKEND_URL || '').trim()
    if (configured) {
        return configured.replace(/\/+$/, '')
    }

    // In the browser, use relative paths to allow the Next.js proxy to work
    // This is essential for deployments behind a single-port proxy like Railway
    if (typeof window !== 'undefined') {
        return ''
    }

    return 'http://127.0.0.1:8000'
}

export function apiUrl(path: string): string {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`
    const baseUrl = getApiBaseUrl()
    return `${baseUrl}${normalizedPath}`
}
