package mv.aegis;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Feature 6 — spyware / stalkerware scanner.
 *
 * <p>Enumerates installed apps and scores each one for stalkerware-like behavior. Detection combines
 * a bundled known-signature list ({@code assets/spyware_signatures.txt}) with a behavioral heuristic
 * built from the signals that actually distinguish stalkerware from ordinary apps:
 * <ul>
 *   <li>a hidden launcher icon (the app hides itself),</li>
 *   <li>an active Accessibility service (can read the screen and inputs),</li>
 *   <li>an active Device Administrator (resists uninstall),</li>
 *   <li>a sideloaded install source (not the Play Store),</li>
 *   <li>a surveillance permission combo (mic/camera + location + messages/contacts).</li>
 * </ul>
 *
 * <p>Because legitimate messengers request the same sensitive permissions as stalkerware, permission
 * breadth alone never reaches HIGH — it must combine with a hiding/persistence signal. Play-Store
 * installs are discounted so mainstream apps land at LOW rather than being falsely branded.
 *
 * <p>This class is detection-only and does no I/O beyond PackageManager/Settings reads. Run
 * {@link #scan(Context)} off the main thread. Network blocking of a flagged app is handled by
 * {@link #setNetworkBlocked(Context, int, boolean)}.
 */
public class SpywareScanner {

    private static final String TAG = "Aegis.Spyware";

    // Risk band thresholds (after scoring + source discount).
    private static final int HIGH = 55;
    private static final int MEDIUM = 30;
    private static final int LOW = 18;

    public static final String RISK_KNOWN = "KNOWN";
    public static final String RISK_HIGH = "HIGH";
    public static final String RISK_MEDIUM = "MEDIUM";
    public static final String RISK_LOW = "LOW";

    // Sensitive permissions used both for the surveillance combo and for breadth scoring.
    private static final String P_RECORD_AUDIO = "android.permission.RECORD_AUDIO";
    private static final String P_CAMERA = "android.permission.CAMERA";
    private static final String P_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION";
    private static final String P_BG_LOCATION = "android.permission.ACCESS_BACKGROUND_LOCATION";
    private static final String P_READ_SMS = "android.permission.READ_SMS";
    private static final String P_RECEIVE_SMS = "android.permission.RECEIVE_SMS";
    private static final String P_READ_CALL_LOG = "android.permission.READ_CALL_LOG";
    private static final String P_READ_CONTACTS = "android.permission.READ_CONTACTS";
    private static final String P_READ_PHONE_STATE = "android.permission.READ_PHONE_STATE";
    private static final String P_OUTGOING_CALLS = "android.permission.PROCESS_OUTGOING_CALLS";
    private static final String P_READ_CALENDAR = "android.permission.READ_CALENDAR";
    private static final String P_OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW";
    private static final String P_INSTALL_PKGS = "android.permission.REQUEST_INSTALL_PACKAGES";
    private static final String P_BOOT = "android.permission.RECEIVE_BOOT_COMPLETED";

    private static final String[] SENSITIVE = {
            P_RECORD_AUDIO, P_CAMERA, P_FINE_LOCATION, P_BG_LOCATION, P_READ_SMS, P_RECEIVE_SMS,
            P_READ_CALL_LOG, P_READ_CONTACTS, P_READ_PHONE_STATE, P_OUTGOING_CALLS, P_READ_CALENDAR
    };

    private static final String PLAY_STORE = "com.android.vending";

    /** One scan result. Fields are public for lightweight consumption by the UI. */
    public static class Finding {
        public String packageName;
        public String label;
        public int uid;
        public boolean system;
        public boolean knownSignature;
        public boolean hiddenIcon;
        public boolean accessibility;
        public boolean deviceAdmin;
        public boolean sideloaded;
        public int score;
        public String risk;                 // RISK_* constant
        public List<String> reasons = new ArrayList<>();
        public boolean networkBlocked;      // current firewall state for this package
        public Drawable icon;               // may be null
    }

    /**
     * Scans all user-installed apps (plus any app matching a known signature) and returns findings
     * of LOW risk or higher, sorted most-severe first. Never returns null.
     */
    public List<Finding> scan(Context ctx) {
        List<Finding> out = new ArrayList<>();
        if (ctx == null) {
            return out;
        }
        PackageManager pm = ctx.getPackageManager();
        String self = ctx.getPackageName();
        Set<String> signatures = loadSignatures(ctx);
        Set<String> accessibilityPkgs = enabledAccessibilityPackages(ctx);
        Set<String> adminPkgs = deviceAdminPackages(ctx);

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (Throwable t) {
            Log.e(TAG, "getInstalledPackages failed", t);
            return out;
        }

        for (PackageInfo pi : packages) {
            try {
                if (pi == null || pi.applicationInfo == null || pi.packageName == null) {
                    continue;
                }
                String pkg = pi.packageName;
                if (pkg.equals(self)) {
                    continue;
                }
                boolean system = (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean known = signatures.contains(pkg.toLowerCase(Locale.ROOT));
                // Focus on user-installed apps; skip system apps unless explicitly known-bad.
                if (system && !known) {
                    continue;
                }
                Finding f = evaluate(ctx, pm, pi, system, known, accessibilityPkgs, adminPkgs);
                if (f != null) {
                    out.add(f);
                }
            } catch (Throwable t) {
                Log.w(TAG, "evaluate failed for " + (pi == null ? "?" : pi.packageName), t);
            }
        }

        Collections.sort(out, new Comparator<Finding>() {
            @Override
            public int compare(Finding a, Finding b) {
                if (a.knownSignature != b.knownSignature) {
                    return a.knownSignature ? -1 : 1;
                }
                return Integer.compare(b.score, a.score);
            }
        });
        return out;
    }

    private Finding evaluate(Context ctx, PackageManager pm, PackageInfo pi, boolean system,
                             boolean known, Set<String> accessibilityPkgs, Set<String> adminPkgs) {
        String pkg = pi.packageName;
        Set<String> req = new HashSet<>();
        if (pi.requestedPermissions != null) {
            for (String p : pi.requestedPermissions) {
                if (p != null) {
                    req.add(p);
                }
            }
        }

        int sensitiveCount = 0;
        for (String p : SENSITIVE) {
            if (req.contains(p)) {
                sensitiveCount++;
            }
        }

        boolean audioOrCam = req.contains(P_RECORD_AUDIO) || req.contains(P_CAMERA);
        boolean location = req.contains(P_FINE_LOCATION) || req.contains(P_BG_LOCATION);
        boolean comms = req.contains(P_READ_SMS) || req.contains(P_RECEIVE_SMS)
                || req.contains(P_READ_CALL_LOG) || req.contains(P_READ_CONTACTS);
        boolean surveillanceCombo = audioOrCam && location && comms;

        boolean hasLauncher = false;
        try {
            hasLauncher = pm.getLaunchIntentForPackage(pkg) != null;
        } catch (Throwable ignored) {
            // treat as no launcher
        }
        boolean hiddenIcon = !hasLauncher && sensitiveCount >= 1;
        boolean accessibility = accessibilityPkgs.contains(pkg);
        boolean deviceAdmin = adminPkgs.contains(pkg);
        boolean trusted = isTrustedSource(pm, pkg);
        boolean sideloaded = !trusted && !system;

        Finding f = new Finding();
        f.packageName = pkg;
        f.uid = pi.applicationInfo.uid;
        f.system = system;
        f.knownSignature = known;
        f.hiddenIcon = hiddenIcon;
        f.accessibility = accessibility;
        f.deviceAdmin = deviceAdmin;
        f.sideloaded = sideloaded;
        try {
            f.label = pm.getApplicationLabel(pi.applicationInfo).toString();
        } catch (Throwable ignored) {
            f.label = pkg;
        }
        try {
            f.icon = pm.getApplicationIcon(pi.applicationInfo);
        } catch (Throwable ignored) {
            f.icon = null;
        }
        try {
            f.networkBlocked = ctx.getSharedPreferences("wifi", Context.MODE_PRIVATE)
                    .getBoolean(pkg, false);
        } catch (Throwable ignored) {
            f.networkBlocked = false;
        }

        if (known) {
            f.score = 100;
            f.risk = RISK_KNOWN;
            f.reasons.add("Matches a known stalkerware/spyware signature");
            addContextReasons(f, surveillanceCombo, sensitiveCount);
            return f;
        }

        int score = 0;
        if (hiddenIcon) {
            score += 40;
            f.reasons.add("Hides itself — no icon in the app launcher");
        }
        if (accessibility) {
            score += 30;
            f.reasons.add("Runs an Accessibility service (can read the screen and your input)");
        }
        if (deviceAdmin) {
            score += 25;
            f.reasons.add("Registered as a Device Administrator (resists uninstall)");
        }
        if (sideloaded) {
            score += 20;
            f.reasons.add("Installed from outside the Play Store");
        }
        if (surveillanceCombo) {
            score += 20;
            f.reasons.add("Can record audio/camera, track location, and read messages or contacts");
        }
        if (sensitiveCount > 3) {
            int breadth = Math.min((sensitiveCount - 3) * 3, 15);
            score += breadth;
            f.reasons.add("Requests " + sensitiveCount + " sensitive permissions");
        }
        if (req.contains(P_OVERLAY)) {
            score += 8;
            f.reasons.add("Can draw over other apps");
        }
        if (req.contains(P_INSTALL_PKGS)) {
            score += 8;
            f.reasons.add("Can install other apps");
        }
        if (req.contains(P_BOOT)) {
            score += 5;
            f.reasons.add("Starts automatically on boot");
        }

        // Play-Store apps are far less likely to be stalkerware — discount so mainstream
        // messengers with broad permissions don't land as HIGH.
        if (trusted) {
            score -= 25;
            if (score < 0) {
                score = 0;
            }
        }

        f.score = score;
        if (score >= HIGH) {
            f.risk = RISK_HIGH;
        } else if (score >= MEDIUM) {
            f.risk = RISK_MEDIUM;
        } else if (score >= LOW) {
            f.risk = RISK_LOW;
        } else {
            return null; // below reporting threshold
        }
        if (f.reasons.isEmpty()) {
            f.reasons.add("Uses sensitive permissions");
        }
        return f;
    }

    private void addContextReasons(Finding f, boolean surveillanceCombo, int sensitiveCount) {
        if (f.hiddenIcon) {
            f.reasons.add("Hides itself — no icon in the app launcher");
        }
        if (f.accessibility) {
            f.reasons.add("Runs an Accessibility service");
        }
        if (f.deviceAdmin) {
            f.reasons.add("Registered as a Device Administrator");
        }
        if (surveillanceCombo) {
            f.reasons.add("Can record audio/camera, track location, and read messages or contacts");
        }
    }

    /**
     * Blocks (or unblocks) all packages sharing {@code uid} on both Wi-Fi and mobile data. The caller
     * is responsible for asking a running {@link FirewallService} to reload afterward. Enforcement is
     * per-uid, so every package of the uid must be set for the block to hold.
     */
    public static void setNetworkBlocked(Context ctx, int uid, boolean blocked) {
        if (ctx == null) {
            return;
        }
        PackageManager pm = ctx.getPackageManager();
        String[] pkgs = null;
        try {
            pkgs = pm.getPackagesForUid(uid);
        } catch (Throwable ignored) {
            // fall through
        }
        if (pkgs == null || pkgs.length == 0) {
            return;
        }
        android.content.SharedPreferences.Editor wifi =
                ctx.getSharedPreferences("wifi", Context.MODE_PRIVATE).edit();
        android.content.SharedPreferences.Editor other =
                ctx.getSharedPreferences("other", Context.MODE_PRIVATE).edit();
        for (String p : pkgs) {
            if (p == null) {
                continue;
            }
            wifi.putBoolean(p, blocked);
            other.putBoolean(p, blocked);
        }
        wifi.apply();
        other.apply();
    }

    private static Set<String> loadSignatures(Context ctx) {
        Set<String> out = new HashSet<>();
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(ctx.getAssets().open("spyware_signatures.txt")));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                out.add(line.toLowerCase(Locale.ROOT));
            }
        } catch (Throwable t) {
            Log.w(TAG, "signature list unavailable", t);
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
        return out;
    }

    private static Set<String> enabledAccessibilityPackages(Context ctx) {
        Set<String> out = new HashSet<>();
        try {
            String flat = Settings.Secure.getString(ctx.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (flat != null) {
                for (String comp : flat.split(":")) {
                    if (comp == null || comp.isEmpty()) {
                        continue;
                    }
                    ComponentName cn = ComponentName.unflattenFromString(comp);
                    if (cn != null) {
                        out.add(cn.getPackageName());
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "accessibility read failed", t);
        }
        return out;
    }

    private static Set<String> deviceAdminPackages(Context ctx) {
        Set<String> out = new HashSet<>();
        try {
            DevicePolicyManager dpm =
                    (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                List<ComponentName> admins = dpm.getActiveAdmins();
                if (admins != null) {
                    for (ComponentName cn : admins) {
                        if (cn != null) {
                            out.add(cn.getPackageName());
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "device admin read failed", t);
        }
        return out;
    }

    private static boolean isTrustedSource(PackageManager pm, String pkg) {
        try {
            String installer;
            if (Build.VERSION.SDK_INT >= 30) {
                installer = pm.getInstallSourceInfo(pkg).getInstallingPackageName();
            } else {
                installer = pm.getInstallerPackageName(pkg);
            }
            return PLAY_STORE.equals(installer);
        } catch (Throwable t) {
            return false;
        }
    }
}
