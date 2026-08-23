package mv.aegis;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.net.VpnService.Builder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import com.mv.aegis.R;

public class FirewallService extends VpnService {

    static {
        System.loadLibrary("aegiscore");
    }

    public enum Command {
        run,
        start,
        reload,
        reload_blocklist,
        stop
    }

    public static final String EXTRA_COMMAND = "Command";
    public static final String EXTRA_REASON = "Reason";
    public static final String EXTRA_TEMPORARY = "Temporary";
    public static final String EXTRA_INTERACTIVE = "Interactive";

    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_WAITING = 2;
    private static final int NOTIFY_DISABLED = 3;
    private static final int NOTIFY_ERROR = 6;
    // Threat alerts use IDs well above the fixed foreground IDs (1/2/3/6) to avoid collisions.
    private static final int NOTIFY_THREAT_BASE = 1000;

    private static final String TAG = "FirewallService";
    private static final String CHANNEL_ID_FOREGROUND = "foreground";
    private static final String CHANNEL_ID_THREATS = "threats";

    private enum State {
        none,
        waiting,
        enforcing
    }

    private State state = State.none;
    private ParcelFileDescriptor vpn = null;
    private ParcelFileDescriptor tunFd = null;
    private List<FirewallRule> currentRules = null;
    private boolean temporarilyStopped = false;
    private volatile Looper commandLooper;
    private volatile CommandHandler commandHandler;
    private static Object jni_lock = new Object();
    private static long jni_context = 0;
    private Thread tunnelThread = null;
    private ThreatDetector threatDetector;
    private final ConcurrentHashMap<String, Integer> recentDomainUid = new ConcurrentHashMap<>();

    private native long jni_init(int sdk);

    private native void jni_start(long context, int loglevel);

    private native void jni_run(long context, int tun, boolean fwd53, int rcode);

    private native void jni_stop(long context);

    private native void jni_clear(long context);

    private native int jni_get_mtu();

    private native void jni_done(long context);


    private final class CommandHandler extends Handler {

        private CommandHandler(Looper looper) {
            super(looper);
        }

        private void queue(Intent intent) {
            Command command = getCommand(intent);
            if (command == null) {
                return;
            }
            Message message = obtainMessage(command.ordinal(), intent);
            sendMessage(message);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                synchronized (FirewallService.this) {
                    handleIntent((Intent) msg.obj);
                }
            } catch (Throwable throwable) {
                Log.e(TAG, "Failed to handle command", throwable);
            }
        }

        private void handleIntent(Intent intent) {
            Log.d(TAG, "handleIntent command=" + getCommand(intent));
             Command command = getCommand(intent);
             if (command == null) {
                 return;
             }

             switch (command) {
                 case start:
                     start();
                     break;
                 case reload:
                     reload(intent.getBooleanExtra(EXTRA_INTERACTIVE, false));
                     break;
                 case reload_blocklist:
                     if (threatDetector != null) {
                         threatDetector.reload();
                     }
                     break;
                 case stop:
                     temporarilyStopped = intent.getBooleanExtra(EXTRA_TEMPORARY, false);
                     stop(temporarilyStopped);
                     break;
                 case run:
                 default:
                     break;
             }
        }
    }

    private void start() {
        Log.d(TAG, "start() BEGIN");
        currentRules = FirewallRule.getRules(false, this);  // ← add this
        if (vpn == null) {
            stopForeground(true);
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification());
        }
        state = State.enforcing;

        Intent configureIntent = new Intent().setClassName(this, "mv.aegis.HomeActivity");
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                0,
                configureIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));
        builder.addAddress("10.1.10.1", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.setMtu(jni_get_mtu());
        builder.setConfigureIntent(pendingIntent);
        // Exclude Aegis itself so its traffic bypasses the VPN tunnel
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (Exception e) {
            Log.e(TAG, "Failed to exclude self from VPN", e);
        }
        Log.d(TAG, "jni_start called, context=" + jni_context);
        jni_start(jni_context, Log.DEBUG);  // Log.DEBUG = 3 — enables packet logging

        if (tunFd != null && tunFd.getFileDescriptor().valid()) {
            try {
                tunFd.close();
            } catch (Exception exception) {
                Log.w(TAG, "Failed to close tunFd before establish", exception);
            }
            tunFd = null;
        }

        Log.d(TAG, "builder config: " + builder.toString());
        Log.d(TAG, "VPN establish called");
        tunFd = builder.establish();
        if (tunFd == null) {
            Log.e(TAG, "establish() returned null — VPN builder config invalid");
            return;
        }
        Log.d(TAG, "establish() succeeded, tun fd=" + tunFd.getFd());
        vpn = tunFd;
        if (tunFd == null) {
             throw new IllegalStateException("VPN establish failed");
         }

        // Read default policy from SharedPreferences
        // Default allow is the inverse of whitelist mode preference
        SharedPreferences sp = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        boolean whitelist_wifi = sp.getBoolean("whitelist_wifi", false);
        boolean whitelist_other = sp.getBoolean("whitelist_other", false);
        boolean whitelist_roaming = sp.getBoolean("whitelist_roaming", false);
        boolean default_allow_wifi = !whitelist_wifi;
        boolean default_allow_other = !whitelist_other;
        boolean default_allow_roaming = !whitelist_roaming;
        Log.d(TAG, "start() - Setting default policy: wifi=" + default_allow_wifi + " other=" + default_allow_other + " roaming=" + default_allow_roaming);


        if (tunnelThread != null && tunnelThread.isAlive()) {
            return;
        }

        tunnelThread = new Thread(() -> {
            if (tunFd == null || !tunFd.getFileDescriptor().valid()) {
                Log.w(TAG, "jni_run skipped: tunFd is null or closed");
                return;
            }
            int tun = tunFd.getFd();
            Log.d(TAG, "jni_run called, tun=" + tun);
            jni_run(jni_context, tun, false, 3);
        }, "FirewallTunnel");
        tunnelThread.start();
    }

    private void reload(boolean interactive) {
        currentRules = FirewallRule.getRules(false, this);
        Log.d(TAG, "reload() - Reloaded firewall rules: " + (currentRules == null ? 0 : currentRules.size()));

    }

    private void stop(boolean temporary) {
        if (vpn != null) {
            jni_stop(jni_context);
            try {
                vpn.close();
            } catch (Exception exception) {
                Log.w(TAG, "Failed to close VPN", exception);
            }
            vpn = null;
        }

        if (state == State.enforcing && !temporary) {
            stopForeground(true);
            state = State.none;
            stopSelf();
        }
    }

    private Notification getEnforcingNotification() {
        Intent intent = new Intent().setClassName(this, "mv.aegis.HomeActivity");
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID_FOREGROUND)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setOngoing(true)
                .setContentTitle(getString(R.string.app_name))
                .setContentText("Firewall active")
                .setContentIntent(pendingIntent)
                .build();
    }

    private Notification getWaitingNotification() {
        Intent intent = new Intent().setClassName(this, "mv.aegis.HomeActivity");
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID_FOREGROUND)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setOngoing(true)
                .setContentTitle(getString(R.string.app_name))
                .setContentText("Firewall waiting")
                .setContentIntent(pendingIntent)
                .build();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ensureForegroundChannel();
        ensureThreatChannel();

        state = State.waiting;
        startForeground(NOTIFY_WAITING, getWaitingNotification());

        synchronized (jni_lock) {
            Log.d(TAG, "jni_init called");
            jni_context = jni_init(Build.VERSION.SDK_INT);
        }

        HandlerThread handlerThread = new HandlerThread("AegisCommand", android.os.Process.THREAD_PRIORITY_FOREGROUND);
        handlerThread.start();
        commandLooper = handlerThread.getLooper();
        commandHandler = new CommandHandler(commandLooper);

        threatDetector = new ThreatDetector(this);
        new Thread(() -> {
            try {
                threatDetector.load();
            } catch (Throwable t) {
                Log.e(TAG, "ThreatDetector load failed", t);
            }
        }, "AegisThreatLoad").start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (state == State.enforcing) {
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification());
        } else {
            startForeground(NOTIFY_WAITING, getWaitingNotification());
        }

        if (intent == null) {
            intent = new Intent(this, FirewallService.class);
            intent.putExtra(EXTRA_COMMAND, Command.stop);
        }

        Command command = getCommand(intent);
        if (command != null) {
            commandHandler.queue(intent);
        }

        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        getSharedPreferences("aegis", MODE_PRIVATE)
                .edit()
                .putBoolean("enabled", false)
                .apply();

        stop(false);
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        if (commandLooper != null) {
            commandLooper.quitSafely();
            commandLooper = null;
        }

        if (vpn != null) {
            try {
                vpn.close();
            } catch (Exception exception) {
                Log.w(TAG, "Failed to close VPN on destroy", exception);
            }
            vpn = null;
        }

        synchronized (jni_lock) {
            if (jni_context != 0) {
                jni_done(jni_context);
                jni_context = 0;
            }
        }

        super.onDestroy();
    }

    public static void start(String reason, Context context) {
        Intent intent = createIntent(context, Command.start, reason);
        startForegroundServiceCompat(context, intent);
    }

    public static void stop(String reason, Context context, boolean temporary) {
        Intent intent = createIntent(context, Command.stop, reason);
        intent.putExtra(EXTRA_TEMPORARY, temporary);
        startForegroundServiceCompat(context, intent);
    }

    public static void reload(String reason, Context context, boolean interactive) {
        Intent intent = createIntent(context, Command.reload, reason);
        intent.putExtra(EXTRA_INTERACTIVE, interactive);
        startForegroundServiceCompat(context, intent);
    }

    /**
     * Tells a RUNNING service to refresh its in-memory blocklist from the database after the
     * user edits it in the in-app manager. Callers should only invoke this while the firewall
     * is enabled; when it is off the service is stopped and reloads on its next start.
     */
    public static void reloadBlocklist(String reason, Context context) {
        Intent intent = createIntent(context, Command.reload_blocklist, reason);
        startForegroundServiceCompat(context, intent);
    }

    public static void run(String reason, Context context) {
        Intent intent = createIntent(context, Command.run, reason);
        startForegroundServiceCompat(context, intent);
    }

    private static Intent createIntent(Context context, Command command, String reason) {
        Intent intent = new Intent(context, FirewallService.class);
        intent.putExtra(EXTRA_COMMAND, command);
        intent.putExtra(EXTRA_REASON, reason);
        return intent;
    }

    private static void startForegroundServiceCompat(Context context, Intent intent) {
        try {
            ContextCompat.startForegroundService(context, intent);
        } catch (RuntimeException runtimeException) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                    && runtimeException instanceof android.app.ForegroundServiceStartNotAllowedException) {
                context.startService(intent);
                return;
            }
            throw runtimeException;
        }
    }

    private Command getCommand(Intent intent) {
        if (intent == null) {
            return null;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getSerializableExtra(EXTRA_COMMAND, Command.class);
        }

        Bundle extras = intent.getExtras();
        if (extras == null) {
            return null;
        }

        Object value = extras.get(EXTRA_COMMAND);
        if (value instanceof Command) {
            return (Command) value;
        }

        return null;
    }

    private void ensureForegroundChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }

        NotificationManager notificationManager = getSystemService(NotificationManager.class);
        if (notificationManager == null) {
            return;
        }

        NotificationChannel channel = notificationManager.getNotificationChannel(CHANNEL_ID_FOREGROUND);
        if (channel != null) {
            return;
        }

        NotificationChannel foregroundChannel = new NotificationChannel(
                CHANNEL_ID_FOREGROUND,
                getString(R.string.app_name),
                NotificationManager.IMPORTANCE_LOW
        );
        notificationManager.createNotificationChannel(foregroundChannel);
    }

    private void ensureThreatChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }

        NotificationManager notificationManager = getSystemService(NotificationManager.class);
        if (notificationManager == null) {
            return;
        }

        if (notificationManager.getNotificationChannel(CHANNEL_ID_THREATS) != null) {
            return;
        }

        NotificationChannel threatChannel = new NotificationChannel(
                CHANNEL_ID_THREATS,
                "Threat alerts",
                NotificationManager.IMPORTANCE_HIGH
        );
        threatChannel.setDescription(
                "Alerts when Aegis blocks a malicious domain or flags a lookalike domain.");
        notificationManager.createNotificationChannel(threatChannel);
    }

    /**
     * Posts a heads-up notification describing a detected threat and why. Blocklist hits
     * are reported as blocked; typosquat hits are reported as flagged (not blocked).
     * No-op if the user hasn't granted notification permission (API 33+).
     */
    private void fireThreatNotification(String domain, String threatType,
                                        boolean blocked, String detail) {
        try {
            if (!AegisUtils.canNotify(this)) {
                return;
            }

            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager == null) {
                return;
            }

            Intent intent = new Intent().setClassName(this, "mv.aegis.HomeActivity");
            PendingIntent pendingIntent = PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            );

            String title = blocked ? "Threat blocked" : "Suspicious domain flagged";

            StringBuilder summary = new StringBuilder();
            summary.append(domain).append(" — ").append(threatType);
            if (detail != null && !detail.isEmpty()) {
                summary.append(" (").append(detail).append(")");
            }

            String why = blocked
                    ? "Aegis blocked a connection to a known malicious domain."
                    : "Aegis flagged a domain that looks like a trusted brand. It was not "
                            + "blocked automatically — open Aegis to review.";

            Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID_THREATS)
                    .setSmallIcon(R.drawable.ic_security_white_24dp)
                    .setContentTitle(title)
                    .setContentText(summary.toString())
                    .setStyle(new NotificationCompat.BigTextStyle()
                            .bigText(summary + "\n\n" + why))
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setAutoCancel(true)
                    .setContentIntent(pendingIntent)
                    .build();

            String key = ThreatDetector.normalize(domain);
            int id = NOTIFY_THREAT_BASE + Math.abs((key == null ? domain : key).hashCode() % 100000);
            notificationManager.notify(id, notification);
        } catch (Throwable t) {
            Log.e(TAG, "fireThreatNotification failed for " + domain, t);
        }
    }

    public boolean protect(int socket) {
        boolean result = super.protect(socket);
        Log.d(TAG, "protect socket=" + socket + " result=" + result);
        return result;
    }

    public Allowed isAddressAllowed(Packet packet) {
        Log.d(TAG, "isAddressAllowed called for uid=" + packet.uid);
        if (packet == null) {
            return null;
        }

        boolean isWifi = AegisUtils.isWifiActive(this);
        FirewallRule matchedRule = null;
        List<FirewallRule> rules = currentRules;
        if (rules != null) {
            for (FirewallRule rule : rules) {
                if (rule.uid == packet.uid) {
                    matchedRule = rule;
                    break;
                }
            }
        }

        boolean blocked;
        if (matchedRule != null) {
            blocked = isWifi ? matchedRule.wifi_blocked : matchedRule.other_blocked;
        } else {
            SharedPreferences sp = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
            boolean whitelist_wifi = sp.getBoolean("whitelist_wifi", false);
            boolean whitelist_other = sp.getBoolean("whitelist_other", false);
            boolean whitelist = isWifi ? whitelist_wifi : whitelist_other;
            blocked = whitelist;
        }

        packet.allowed = !blocked;
        return blocked ? null : new Allowed();
    }

    public boolean isDomainBlocked(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        try {
            if (threatDetector != null) {
                if (threatDetector.isBlocklisted(name)) {
                    onThreatDetected(name, ThreatDetector.THREAT_BLOCKLIST, true, null);
                    return true; // known-bad -> auto-block
                }
                String impersonated = threatDetector.typosquatTarget(name);
                if (impersonated != null) {
                    // Lookalike domain: flag only, do NOT block.
                    onThreatDetected(name, ThreatDetector.THREAT_TYPOSQUAT, false,
                            "lookalike of " + impersonated);
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "isDomainBlocked check failed for " + name, t);
        }
        return false;
    }

    private void onThreatDetected(String domain, String threatType, boolean blocked, String detail) {
        try {
            if (threatDetector == null || !threatDetector.shouldReport(threatType, domain)) {
                return;
            }
            Log.w(TAG, "Threat detected (" + threatType + "): " + domain + " blocked=" + blocked
                    + (detail == null ? "" : " [" + detail + "]"));

            Packet packet = new Packet();
            packet.time = System.currentTimeMillis();
            packet.version = 4;
            packet.protocol = 17; // mark as UDP so the row is visible in the standard log viewer
            packet.flags = "";
            packet.saddr = "";
            packet.sport = 0;
            packet.daddr = "";
            packet.dport = 0;
            packet.data = detail == null ? "" : detail;
            packet.uid = recentUidForDomain(domain);
            packet.allowed = !blocked;

            AegisDatabase.getInstance(this)
                    .insertThreatLog(packet, domain, threatType, 0, AegisUtils.isInteractive(this));

            fireThreatNotification(domain, threatType, blocked, detail);
        } catch (Throwable t) {
            Log.e(TAG, "onThreatDetected failed for " + domain, t);
        }
    }

    private int recentUidForDomain(String domain) {
        String key = ThreatDetector.normalize(domain);
        if (key == null) {
            return -1;
        }
        Integer uid = recentDomainUid.get(key);
        return uid == null ? -1 : uid;
    }

    public int getUidQ(int version, int protocol, String saddr, int sport, String daddr, int dport) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return -1;
        }

        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return -1;
        }

        try {
            InetSocketAddress local = new InetSocketAddress(saddr, sport);
            InetSocketAddress remote = new InetSocketAddress(daddr, dport);
            return cm.getConnectionOwnerUid(protocol, local, remote);
        } catch (Exception exception) {
            Log.w(TAG, "getUidQ failed for " + saddr + ":" + sport + " -> " + daddr + ":" + dport, exception);
            return -1;
        }
    }

    public void logPacket(Packet packet) {
        if (packet == null) return;
        Log.d(TAG, "logPacket uid=" + packet.uid + " daddr=" + packet.daddr);
        AegisDatabase.getInstance(this)
                .insertLog(packet, null, 0, AegisUtils.isInteractive(this));
    }

    public void dnsResolved(ResourceRecord rr) {
        if (rr == null) {
            return;
        }

        ContentValues cv = new ContentValues();
        cv.put("time", rr.Time);
        cv.put("qname", rr.QName);
        cv.put("aname", rr.AName);
        cv.put("resource", rr.Resource);
        cv.put("ttl", rr.TTL);
        cv.put("uid", rr.uid);

        SQLiteDatabase db = AegisDatabase.getInstance(this).getWritableDatabase();
        db.insertWithOnConflict("dns", null, cv, SQLiteDatabase.CONFLICT_REPLACE);

        // Best-effort domain -> uid attribution for threat logging (Feature 1/4).
        // uid is real in the TLS SNI path (ip.c) and -1 in the DNS-answer path (dns.c).
        if (rr.uid >= 0 && rr.QName != null) {
            String key = ThreatDetector.normalize(rr.QName);
            if (key != null && !key.isEmpty()) {
                if (recentDomainUid.size() > 5000) {
                    recentDomainUid.clear();
                }
                recentDomainUid.put(key, rr.uid);
            }
        }
    }

    public void accountUsage(Usage usage) {
        if (usage == null) {
            return;
        }

        AegisDatabase.getInstance(this).updateUsage(usage, null);
    }

    public void nativeExit(String reason) {
        Log.w(TAG, "nativeExit: " + reason);
        stop(false);
    }

    public void nativeError(int error, String message) {
        Log.e(TAG, "nativeError " + error + ": " + message);
    }
}
