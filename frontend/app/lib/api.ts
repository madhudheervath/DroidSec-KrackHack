export function getApiBaseUrl(): string {
    const configured = (process.env.NEXT_PUBLIC_BACKEND_URL || '').trim()
    if (configured) {
        return configured.replace(/\/+$/, '')
    }

    const localBackend = 'http://127.0.0.1:8000'

    // In local development, call backend directly so Next proxy/cache issues
    // do not break uploads.
    if (process.env.NODE_ENV !== 'production') {
        return localBackend
    }

    // In production browser, keep same-origin paths so Railway serves a single domain.
    if (typeof window !== 'undefined') {
        return ''
    }

    // Server-side production fallback for rewrites/SSR paths.
    return (process.env.BACKEND_INTERNAL_URL || localBackend).replace(/\/+$/, '')
}

export function apiUrl(path: string): string {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`
    const baseUrl = getApiBaseUrl()
    return `${baseUrl}${normalizedPath}`
}
