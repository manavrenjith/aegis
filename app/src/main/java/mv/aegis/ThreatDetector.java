package mv.aegis;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central cyber-threat detection helper for Aegis.
 *
 * <p>Feature 1 (this file): loads a bundled malicious-domain blocklist
 * ({@code assets/blocklist.txt}) into the SQLite {@code blocklist} table on first
 * run, keeps it in an in-memory set, and offers a fast exact-match lookup used by
 * {@link FirewallService#isDomainBlocked(String)} on the packet thread.
 *
 * <p>All lookups are backed by in-memory structures only — no per-packet SQLite
 * access — because they run on the VPN tunnel thread.
 */
public class ThreatDetector {
    private static final String TAG = "Aegis.ThreatDetector";
    private static final String BLOCKLIST_ASSET = "blocklist.txt";

    /** threat_type value stored for exact blocklist matches. */
    public static final String THREAT_BLOCKLIST = "known phishing domain";

    /** threat_type value stored for lookalike/typosquat matches (flagged, not blocked). */
    public static final String THREAT_TYPOSQUAT = "possible lookalike domain";

    /**
     * Domains commonly spoofed in India/UPI phishing (banks, UPI apps, popular brands).
     * Kept short and easy to edit. A DNS lookup within a small edit distance of one of
     * these — but not an exact match or a legitimate subdomain — is flagged as a possible
     * lookalike. Detection only: these are never auto-blocked.
     */
    private static final String[] PROTECTED_DOMAINS = {
            // UPI / payments
            "paytm.com", "phonepe.com", "bharatpe.com", "mobikwik.com", "npci.org.in",
            // Banks (India)
            "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
            "kotak.com", "bankofbaroda.in", "pnbindia.in", "canarabank.com",
            // Popular apps / global brands
            "google.com", "gmail.com", "youtube.com", "whatsapp.com", "instagram.com",
            "facebook.com", "amazon.in", "amazon.com", "flipkart.com", "netflix.com",
            "apple.com", "microsoft.com", "paypal.com"
    };

    /** Max edit distance for a lookalike match. Tunable. */
    private static final int MAX_TYPOSQUAT_DISTANCE = 2;

    private static final Set<String> PROTECTED_EXACT = new HashSet<>();

    static {
        for (String d : PROTECTED_DOMAINS) {
            PROTECTED_EXACT.add(d);
        }
    }

    /** Don't log/notify the same (threatType, domain) more than once per window. */
    private static final long REPORT_THROTTLE_MS = 60_000L;

    private final Context context;

    // Exact-match blocklist, normalized (lowercase, no trailing dot). Thread-safe.
    private final Set<String> blocklist =
            Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    // Throttle map keyed by "threatType|domain" -> last report time (ms).
    private final ConcurrentHashMap<String, Long> lastReported = new ConcurrentHashMap<>();

    private volatile boolean loaded = false;

    public ThreatDetector(Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * Seeds the blocklist table from the bundled asset on first run, then loads all
     * blocklisted domains into memory. Safe to call off the main thread; call once
     * when the service starts.
     */
    public synchronized void load() {
        AegisDatabase db = AegisDatabase.getInstance(context);

        try {
            if (db.getBlocklistCount() == 0) {
                List<String> domains = readBlocklistAsset();
                int inserted = db.insertBlocklistDomains(domains, "bundled");
                Log.i(TAG, "Seeded blocklist table with " + inserted
                        + " domains from asset (" + domains.size() + " parsed)");
            }
        } catch (Throwable t) {
            Log.e(TAG, "Failed to seed blocklist from asset", t);
        }

        try {
            Set<String> fromDb = db.loadBlocklistDomains();
            blocklist.clear();
            blocklist.addAll(fromDb);
            loaded = true;
            Log.i(TAG, "Loaded " + blocklist.size() + " blocklisted domains into memory");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to load blocklist into memory", t);
        }
    }

    /**
     * Re-reads the blocklist from the database into the in-memory set, WITHOUT re-seeding from
     * the bundled asset. Called after the user edits the blocklist in the in-app manager so the
     * running tunnel thread picks up additions/removals immediately (see
     * {@link FirewallService} {@code reload_blocklist} command). Cheap: one indexed table read.
     */
    public synchronized void reload() {
        try {
            Set<String> fromDb = AegisDatabase.getInstance(context).loadBlocklistDomains();
            blocklist.clear();
            blocklist.addAll(fromDb);
            loaded = true;
            Log.i(TAG, "Reloaded " + blocklist.size() + " blocklisted domains into memory");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to reload blocklist into memory", t);
        }
    }

    /** True if {@code domain} is an exact match against the loaded blocklist. */
    public boolean isBlocklisted(String domain) {
        if (!loaded) {
            return false;
        }
        String normalized = normalize(domain);
        if (normalized == null || normalized.isEmpty()) {
            return false;
        }
        return blocklist.contains(normalized);
    }

    /** Number of domains currently held in memory (for diagnostics/tests). */
    public int size() {
        return blocklist.size();
    }

    public boolean isLoaded() {
        return loaded;
    }

    /**
     * Rate-limits repeated detections of the same domain so the log and (later)
     * notifications aren't spammed when a domain is hit many times in a row.
     *
     * @return true if the caller should record/notify this detection now.
     */
    public boolean shouldReport(String threatType, String domain) {
        String key = threatType + "|" + normalize(domain);
        long now = System.currentTimeMillis();
        Long previous = lastReported.get(key);
        if (previous != null && now - previous < REPORT_THROTTLE_MS) {
            return false;
        }
        lastReported.put(key, now);
        if (lastReported.size() > 5000) {
            lastReported.clear();
        }
        return true;
    }

    /** Lowercases and strips any trailing dot(s). Package-visible for reuse/tests. */
    static String normalize(String domain) {
        if (domain == null) {
            return null;
        }
        String d = domain.trim().toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        return d;
    }

    /**
     * @return the protected brand domain that {@code domain} appears to impersonate,
     *         or null if it is legitimate or not a lookalike. Detection only — callers
     *         must NOT block on this result.
     */
    public String typosquatTarget(String domain) {
        String d = normalize(domain);
        if (d == null || d.length() < 5) {
            return null;
        }
        // Exact legitimate domain -> not a typosquat.
        if (PROTECTED_EXACT.contains(d)) {
            return null;
        }
        // A legitimate subdomain of a protected brand (e.g. accounts.google.com) -> ok.
        for (String p : PROTECTED_DOMAINS) {
            if (d.endsWith("." + p)) {
                return null;
            }
        }
        // Compare the registrable-ish form (drop a leading "www.") against each brand.
        String candidate = d.startsWith("www.") ? d.substring(4) : d;
        if (candidate.length() < 5 || PROTECTED_EXACT.contains(candidate)) {
            return null;
        }

        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String p : PROTECTED_DOMAINS) {
            // Typosquats overwhelmingly preserve the first character; this cuts false
            // positives between unrelated brands (e.g. "ripple" vs "apple").
            if (candidate.charAt(0) != p.charAt(0)) {
                continue;
            }
            // Same registrable name on a different TLD (e.g. "amazon.de" vs "amazon.in")
            // is the same brand, not a lookalike — the edit is entirely in the TLD. Skip.
            if (labelBeforeLastDot(candidate).equals(labelBeforeLastDot(p))) {
                continue;
            }
            if (Math.abs(candidate.length() - p.length()) > MAX_TYPOSQUAT_DISTANCE) {
                continue;
            }
            int distance = levenshtein(candidate, p, MAX_TYPOSQUAT_DISTANCE);
            if (distance >= 1 && distance <= MAX_TYPOSQUAT_DISTANCE && distance < bestDistance) {
                bestDistance = distance;
                best = p;
            }
        }
        return best;
    }

    /** The domain minus its final label (TLD): "amazon.in" -&gt; "amazon", "sbi.co.in" -&gt; "sbi.co". */
    static String labelBeforeLastDot(String domain) {
        int i = domain.lastIndexOf('.');
        return i <= 0 ? domain : domain.substring(0, i);
    }

    /**
     * Bounded Levenshtein edit distance between {@code a} and {@code b}. Returns early
     * with {@code max + 1} as soon as the distance is known to exceed {@code max}.
     */
    static int levenshtein(String a, String b, int max) {
        int la = a.length();
        int lb = b.length();
        if (Math.abs(la - lb) > max) {
            return max + 1;
        }
        int[] prev = new int[lb + 1];
        int[] curr = new int[lb + 1];
        for (int j = 0; j <= lb; j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= la; i++) {
            curr[0] = i;
            int rowMin = curr[0];
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= lb; j++) {
                int cost = (ca == b.charAt(j - 1)) ? 0 : 1;
                int deletion = prev[j] + 1;
                int insertion = curr[j - 1] + 1;
                int substitution = prev[j - 1] + cost;
                int value = Math.min(Math.min(deletion, insertion), substitution);
                curr[j] = value;
                if (value < rowMin) {
                    rowMin = value;
                }
            }
            if (rowMin > max) {
                return max + 1;
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }
        return prev[lb];
    }

    private List<String> readBlocklistAsset() {
        List<String> out = new ArrayList<>();
        AssetManager am = context.getAssets();
        InputStream is = null;
        BufferedReader br = null;
        try {
            is = am.open(BLOCKLIST_ASSET);
            br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String normalized = normalize(trimmed);
                if (normalized != null && !normalized.isEmpty()) {
                    out.add(normalized);
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "readBlocklistAsset failed", t);
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Throwable ignored) {
            }
        }
        return out;
    }
}
