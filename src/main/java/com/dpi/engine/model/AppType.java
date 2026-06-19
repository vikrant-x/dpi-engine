package com.dpi.engine.model;

/**
 * Application type classification — mirrors C++ AppType enum.
 * Mapped from SNI / HTTP Host header / destination port.
 */
public enum AppType {
    UNKNOWN("Unknown", "#94a3b8"),
    HTTP("HTTP", "#3b82f6"),
    HTTPS("HTTPS", "#8b5cf6"),
    DNS("DNS", "#f59e0b"),
    GOOGLE("Google", "#10b981"),
    YOUTUBE("YouTube", "#ef4444"),
    FACEBOOK("Facebook", "#3b82f6"),
    INSTAGRAM("Instagram", "#ec4899"),
    TWITTER("Twitter / X", "#06b6d4"),
    TIKTOK("TikTok", "#f43f5e"),
    NETFLIX("Netflix", "#dc2626"),
    WHATSAPP("WhatsApp", "#22c55e"),
    TELEGRAM("Telegram", "#0ea5e9"),
    GITHUB("GitHub", "#1f2937"),
    AMAZON("Amazon", "#f97316"),
    MICROSOFT("Microsoft", "#0078d4"),
    APPLE("Apple", "#6b7280"),
    CLOUDFLARE("Cloudflare", "#f59e0b"),
    AKAMAI("Akamai", "#7c3aed"),
    OTHER_STREAMING("Streaming", "#8b5cf6"),
    OTHER_SOCIAL("Social Media", "#ec4899"),
    NTP("NTP", "#64748b"),
    QUIC("QUIC/HTTP3", "#a78bfa");

    private final String displayName;
    private final String color;

    AppType(String displayName, String color) {
        this.displayName = displayName;
        this.color = color;
    }

    public String getDisplayName() { return displayName; }
    public String getColor()       { return color; }

    /** Map an SNI hostname to an AppType */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isBlank()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("googlevideo")) return YOUTUBE;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com"))     return FACEBOOK;
        if (s.contains("instagram") || s.contains("cdninstagram"))                      return INSTAGRAM;
        if (s.contains("twitter") || s.contains("x.com") || s.contains("twimg"))        return TWITTER;
        if (s.contains("tiktok") || s.contains("tiktokcdn"))                            return TIKTOK;
        if (s.contains("netflix") || s.contains("nflximg") || s.contains("nflxvideo"))  return NETFLIX;
        if (s.contains("whatsapp"))                                                      return WHATSAPP;
        if (s.contains("telegram") || s.contains("t.me"))                               return TELEGRAM;
        if (s.contains("github") || s.contains("githubusercontent"))                     return GITHUB;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("aws"))       return AMAZON;
        if (s.contains("microsoft") || s.contains("msn") || s.contains("bing"))         return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("itunes"))        return APPLE;
        if (s.contains("cloudflare") || s.contains("1.1.1.1"))                          return CLOUDFLARE;
        if (s.contains("akamai") || s.contains("akadns") || s.contains("akamaiedge"))   return AKAMAI;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis"))  return GOOGLE;
        if (s.contains("twitch") || s.contains("hulu") || s.contains("disney") ||
            s.contains("spotify") || s.contains("primevideo"))                           return OTHER_STREAMING;

        return HTTPS;
    }

    /** Map port to AppType for non-TLS traffic */
    public static AppType fromPort(int dstPort, int protocol) {
        return switch (dstPort) {
            case 80  -> HTTP;
            case 443 -> HTTPS;
            case 53  -> DNS;
            case 123 -> NTP;
            default  -> UNKNOWN;
        };
    }
}
