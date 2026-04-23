import { useState } from 'react'
import { Eye, EyeOff, User, Lock, AlertCircle, ArrowRight, Loader2 } from 'lucide-react'

const IntsecLogo = () => (
  <svg width="64" height="77" viewBox="0 0 400 480" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#0066ff" />
        <stop offset="100%" stopColor="#00d4ff" />
      </linearGradient>
      <linearGradient id="lv" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stopColor="#0066ff" />
        <stop offset="100%" stopColor="#00d4ff" />
      </linearGradient>
      <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur stdDeviation="3" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
    <path d="M40 200 C40 200 120 76 200 76 C280 76 360 200 360 200 C360 200 280 324 200 324 C120 324 40 200 40 200 Z" fill="#0e1525" stroke="url(#lg)" strokeWidth="3.5" />
    <circle cx="200" cy="200" r="84" fill="#0b1220" stroke="url(#lg)" strokeWidth="2.5" />
    <path d="M200 200 L200 116 A84 84 0 0 1 284 200 Z" fill="#0066ff" opacity="0.2" />
    <path d="M200 200 L284 200 A84 84 0 0 1 200 284 Z" fill="#00d4ff" opacity="0.2" />
    <path d="M200 200 L200 284 A84 84 0 0 1 116 200 Z" fill="#0066ff" opacity="0.15" />
    <path d="M200 200 L116 200 A84 84 0 0 1 200 116 Z" fill="#00d4ff" opacity="0.15" />
    <line x1="200" y1="116" x2="200" y2="284" stroke="url(#lv)" strokeWidth="1.2" opacity="0.5" />
    <line x1="116" y1="200" x2="284" y2="200" stroke="url(#lg)" strokeWidth="1.2" opacity="0.5" />
    <circle cx="200" cy="116" r="9" fill="#0e1525" stroke="#00d4ff" strokeWidth="2.5" filter="url(#glow)" />
    <circle cx="284" cy="200" r="9" fill="#0e1525" stroke="#0066ff" strokeWidth="2.5" filter="url(#glow)" />
    <circle cx="200" cy="284" r="9" fill="#0e1525" stroke="#00d4ff" strokeWidth="2.5" filter="url(#glow)" />
    <circle cx="116" cy="200" r="9" fill="#0e1525" stroke="#0066ff" strokeWidth="2.5" filter="url(#glow)" />
    <line x1="40" y1="200" x2="116" y2="200" stroke="url(#lg)" strokeWidth="1.5" opacity="0.4" />
    <line x1="284" y1="200" x2="360" y2="200" stroke="url(#lg)" strokeWidth="1.5" opacity="0.4" />
    <path d="M56 176 L40 200 L56 224" stroke="#0066ff" strokeWidth="2" fill="none" strokeLinecap="round" opacity="0.5" />
    <path d="M344 176 L360 200 L344 224" stroke="#00d4ff" strokeWidth="2" fill="none" strokeLinecap="round" opacity="0.5" />
    <rect x="160" y="206" width="80" height="60" rx="10" fill="url(#lg)" />
    <path d="M176 206 L176 186 C176 168 224 168 224 186 L224 206" stroke="url(#lg)" strokeWidth="12" strokeLinecap="round" fill="none" />
    <circle cx="200" cy="232" r="9" fill="#0a0e1a" />
    <rect x="195.5" y="232" width="9" height="16" rx="2.5" fill="#0a0e1a" />
    <text x="200" y="386" fontFamily="'Space Grotesk','Helvetica Neue',Arial,sans-serif" fontSize="64" fontWeight="700" letterSpacing="-2" textAnchor="middle">
      <tspan fill="#f0f6ff">INT</tspan>
      <tspan fill="#00d4ff">SEC</tspan>
    </text>
    <text x="200" y="422" fontFamily="'Inter','Helvetica Neue',Arial,sans-serif" fontSize="14" fontWeight="400" letterSpacing="4" textAnchor="middle" fill="#3a4d6e">
      INTELLIGENT SECURITY
    </text>
  </svg>
)

function InputField({ id, label, type = 'text', value, onChange, placeholder, icon: Icon, rightElement, hasError }) {
  return (
    <div className="space-y-2">
      <label htmlFor={id} className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest">
        {label}
      </label>
      <div
        className={[
          'flex items-center gap-3 rounded-xl px-4 py-3.5 transition-all duration-200',
          'bg-[#0c1729] border',
          hasError
            ? 'border-red-500/50 bg-red-500/[0.04]'
            : 'border-[#1e2f4a] hover:border-[#2a4060] focus-within:border-cyan-500/60 focus-within:bg-cyan-500/[0.03] focus-within:shadow-[0_0_0_3px_rgba(6,182,212,0.07)]',
        ].join(' ')}
      >
        <Icon size={15} className="text-slate-500 shrink-0" />
        <input
          id={id}
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={id}
          className="flex-1 bg-transparent text-white text-[14px] placeholder:text-slate-600 outline-none"
        />
        {rightElement}
      </div>
    </div>
  )
}

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username || !password) {
      setError('Please fill in all fields.')
      return
    }
    setError('')
    setLoading(true)
    await new Promise((r) => setTimeout(r, 900))

    if (username === 'intsec' && password === 'intsec123') {
      window.location.href = `http://${window.location.hostname}:5601`
    } else {
      setError('Invalid username or password.')
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#040c18] flex items-center justify-center p-4 relative overflow-hidden">

      {/* Background */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-72 -left-72 w-[600px] h-[600px] bg-blue-700/[0.07] rounded-full blur-3xl" />
        <div className="absolute -bottom-72 -right-72 w-[600px] h-[600px] bg-cyan-600/[0.05] rounded-full blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[500px] bg-blue-900/[0.06] rounded-full blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.018]"
          style={{
            backgroundImage: 'radial-gradient(circle, #7dd3fc 1px, transparent 1px)',
            backgroundSize: '32px 32px',
          }}
        />
      </div>

      {/* Card */}
      <div className="relative w-full max-w-[440px]">

        {/* Glow border effect */}
        <div className="absolute -inset-px rounded-[20px] bg-gradient-to-b from-blue-500/[0.18] via-transparent to-cyan-500/[0.08] blur-[2px]" />

        <div className="relative bg-[#06101e] border border-[#112035] rounded-[20px] px-9 py-10 shadow-[0_32px_80px_rgba(0,0,0,0.6)] backdrop-blur-xl">

          {/* Brand row */}
          <div className="flex items-center gap-3.5 mb-9">
            <IntsecLogo />
            <div>
              <div className="text-[17px] font-bold tracking-wide text-white leading-none">
                INT<span className="text-cyan-400">SEC</span>
              </div>
              <div className="text-[10px] font-medium text-slate-500 tracking-[0.18em] uppercase mt-[7px]">
                AI-Enhanced Cyber Attack Classifier
              </div>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2.5 px-4 py-3 mb-6 bg-red-500/[0.07] border border-red-500/25 rounded-xl text-red-400 text-[13px]">
              <AlertCircle size={14} className="shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-5" noValidate>
            <InputField
              id="username"
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              icon={User}
              hasError={error && !username}
            />

            <InputField
              id="current-password"
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              icon={Lock}
              hasError={error && !password}
              rightElement={
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="text-slate-600 hover:text-slate-400 transition-colors focus:outline-none focus-visible:text-slate-300"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              }
            />

            {/* Submit */}
            <div className="pt-1">
              <button
                type="submit"
                disabled={loading}
                className={[
                  'w-full flex items-center justify-center gap-2',
                  'py-[14px] rounded-xl text-[14px] font-semibold text-white tracking-wide',
                  'bg-gradient-to-r from-[#1a5cf8] to-[#00b4d8]',
                  'hover:from-[#1a52e0] hover:to-[#00a0c2]',
                  'active:scale-[0.99] transition-all duration-150',
                  'shadow-[0_4px_24px_rgba(26,92,248,0.25)]',
                  'hover:shadow-[0_4px_28px_rgba(26,92,248,0.35)]',
                  'focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40 focus-visible:ring-offset-2 focus-visible:ring-offset-[#06101e]',
                  'disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100 disabled:shadow-none',
                ].join(' ')}
              >
                {loading ? (
                  <>
                    <Loader2 size={15} className="animate-spin" />
                    Authenticating…
                  </>
                ) : (
                  <>
                    Sign In
                    <ArrowRight size={15} />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Footer */}
          <p className="mt-8 text-center text-[11px] text-slate-700 tracking-wide">
            © 2026 INTSEC · All rights reserved
          </p>

        </div>
      </div>
    </div>
  )
}
