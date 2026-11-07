package mv.aegis;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
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
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

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

    private volatile boolean isInteractive = true;
    private BroadcastReceiver screenReceiver = null;

    private static final class UidDestKey {
        final int uid;
        final String dest;

        UidDestKey(int uid, String dest) {
            this.uid = uid;
            this.dest = dest != null ? dest : "";
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            UidDestKey that = (UidDestKey) o;
            return uid == that.uid && dest.equals(that.dest);
        }

        @Override
        public int hashCode() {
            return 31 * uid + dest.hashCode();
        }
    }

    private static final class UidOverflow {
        final int uid;
        int count = 0;
        final List<String> sampleDestinations = new ArrayList<>(5);
        long lastTimestamp = 0;
        boolean interactive = false;

        UidOverflow(int uid) {
            this.uid = uid;
        }

        void addDestination(String dest, long timestamp, boolean isInteractive) {
            count++;
            this.lastTimestamp = timestamp;
            this.interactive = isInteractive;
            if (sampleDestinations.size() < 5 && dest != null && !dest.isEmpty() && !sampleDestinations.contains(dest)) {
                sampleDestinations.add(dest);
            }
        }
    }

    private static final int QUEUE_SOFT_CAPACITY = 2000;
    private static final int QUEUE_HARD_CAPACITY = 10000;
    private final Object logQueueLock = new Object();
    private final ArrayDeque<AegisDatabase.LogBatchItem> logQueue = new ArrayDeque<>();
    private final Map<UidDestKey, AegisDatabase.LogBatchItem> pendingEntries = new HashMap<>();
    private final LinkedHashMap<UidDestKey, Boolean> seenPairs = new LinkedHashMap<UidDestKey, Boolean>(5000, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<UidDestKey, Boolean> eldest) {
            return size() > 5000;
        }
    };
    private final Map<Integer, UidOverflow> overflowByUid = new HashMap<>();
    private final AtomicLong mergedCount = new AtomicLong(0);
    private final AtomicLong droppedCount = new AtomicLong(0);
    private final AtomicLong unresolvedUidCount = new AtomicLong(0);
    private final AtomicLong overflowCount = new AtomicLong(0);
    private final AtomicLong lostCount = new AtomicLong(0);
    private volatile long lastStatsWarnTime = 0;

    private Thread logBatchThread = null;
    private volatile boolean logBatchRunning = false;

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
        jni_start(jni_context, com.mv.aegis.BuildConfig.DEBUG ? Log.DEBUG : Log.WARN);

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

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        isInteractive = (pm != null && pm.isInteractive());
        screenReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent == null) {
                    return;
                }
                if (Intent.ACTION_SCREEN_ON.equals(intent.getAction())) {
                    isInteractive = true;
                } else if (Intent.ACTION_SCREEN_OFF.equals(intent.getAction())) {
                    isInteractive = false;
                }
            }
        };
        IntentFilter screenFilter = new IntentFilter();
        screenFilter.addAction(Intent.ACTION_SCREEN_ON);
        screenFilter.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(screenReceiver, screenFilter);

        logBatchRunning = true;
        logBatchThread = new Thread(this::runLogBatchWorker, "AegisLogBatch");
        logBatchThread.start();
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

        if (screenReceiver != null) {
            try {
                unregisterReceiver(screenReceiver);
            } catch (Exception ignored) {
            }
            screenReceiver = null;
        }

        logBatchRunning = false;
        if (logBatchThread != null) {
            synchronized (logQueueLock) {
                logQueueLock.notifyAll();
            }
            logBatchThread.interrupt();
            try {
                logBatchThread.join(3000);
            } catch (InterruptedException ignored) {
            }
            logBatchThread = null;
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
                    .insertThreatLog(packet, domain, threatType, 0, isInteractive);

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

    private static UidDestKey getBatchItemKey(AegisDatabase.LogBatchItem item) {
        if (item.packet != null) {
            return new UidDestKey(item.packet.uid, item.packet.daddr != null ? item.packet.daddr : "");
        }
        if (item.usage != null) {
            return new UidDestKey(item.usage.Uid, item.usage.DAddr != null ? item.usage.DAddr : "");
        }
        if (item.rr != null) {
            String d = item.rr.QName != null ? item.rr.QName : (item.rr.Resource != null ? item.rr.Resource : "");
            return new UidDestKey(item.rr.uid, d);
        }
        return new UidDestKey(-1, "");
    }

    private static int getBatchItemUid(AegisDatabase.LogBatchItem item) {
        if (item.packet != null) return item.packet.uid;
        if (item.usage != null) return item.usage.Uid;
        if (item.rr != null) return item.rr.uid;
        return -1;
    }

    private void checkLogStatsWarning() {
        long now = SystemClock.elapsedRealtime();
        if (now - lastStatsWarnTime >= 60000L) {
            long merged = mergedCount.get();
            long dropped = droppedCount.get();
            long unresolved = unresolvedUidCount.get();
            long overflow = overflowCount.get();
            long lost = lostCount.get();
            if (merged > 0 || dropped > 0 || unresolved > 0 || overflow > 0 || lost > 0) {
                Log.w(TAG, "Log queue stats: merged=" + merged + ", dropped=" + dropped + ", unresolved_uid=" + unresolved + ", overflow=" + overflow + ", lost=" + lost);
                lastStatsWarnTime = now;
            }
        }
    }

    private boolean isLogQueueEmpty() {
        synchronized (logQueueLock) {
            return logQueue.isEmpty() && overflowByUid.isEmpty();
        }
    }

    private void enqueueLogItem(AegisDatabase.LogBatchItem item) {
        if (item == null) {
            return;
        }

        // Capture timestamp and screen state at enqueue time
        long now = System.currentTimeMillis();
        boolean interactive = isInteractive;
        item.timestamp = now;
        item.interactive = interactive;
        if (item.packet != null) {
            item.packet.time = now;
        }
        if (item.usage != null) {
            item.usage.Time = now;
        }
        if (item.rr != null) {
            item.rr.Time = now;
        }

        if (item.rr == null) {
            int uid = getBatchItemUid(item);
            if (uid < 0) {
                unresolvedUidCount.incrementAndGet();
            }
        }

        UidDestKey key = getBatchItemKey(item);

        synchronized (logQueueLock) {
            boolean wasEmpty = logQueue.isEmpty();
            boolean isUsageOrDns = (item.usage != null || item.rr != null);

            if (isUsageOrDns) {
                // Usage and DNS items are never dropped or overflowed: always enqueue them
                seenPairs.put(key, Boolean.TRUE);
                logQueue.add(item);
                pendingEntries.put(key, item);
                if (wasEmpty || logQueue.size() == 100) {
                    logQueueLock.notify();
                }
                return;
            }

            int queueSize = logQueue.size();
            if (queueSize < QUEUE_SOFT_CAPACITY) {
                seenPairs.put(key, Boolean.TRUE);
                logQueue.add(item);
                pendingEntries.put(key, item);
                if (wasEmpty || logQueue.size() == 100) {
                    logQueueLock.notify();
                }
            } else if (queueSize < QUEUE_HARD_CAPACITY) {
                if (!seenPairs.containsKey(key)) {
                    // Queue full, but pair not seen: must still be enqueued (exceeds soft limit)
                    seenPairs.put(key, Boolean.TRUE);
                    logQueue.add(item);
                    pendingEntries.put(key, item);
                    if (wasEmpty || logQueue.size() == 100) {
                        logQueueLock.notify();
                    }
                } else {
                    // Already-seen pair: merge into pending entry if one exists, else drop
                    AegisDatabase.LogBatchItem pending = pendingEntries.get(key);
                    if (pending != null) {
                        pending.merge(item);
                        mergedCount.incrementAndGet();
                    } else {
                        droppedCount.incrementAndGet();
                    }
                }
            } else {
                // At hard cap (queueSize >= QUEUE_HARD_CAPACITY)
                if (seenPairs.containsKey(key)) {
                    // Already-seen pair: merge into pending entry if exists, else drop
                    AegisDatabase.LogBatchItem pending = pendingEntries.get(key);
                    if (pending != null) {
                        pending.merge(item);
                        mergedCount.incrementAndGet();
                    } else {
                        droppedCount.incrementAndGet();
                    }
                } else {
                    // New (uid, destination) pair at hard cap: update per-uid overflow aggregation
                    int itemUid = item.packet != null ? item.packet.uid : -1;
                    String dest = item.packet != null && item.packet.daddr != null ? item.packet.daddr : "";
                    UidOverflow overflow = overflowByUid.get(itemUid);
                    if (overflow == null) {
                        overflow = new UidOverflow(itemUid);
                        overflowByUid.put(itemUid, overflow);
                    }
                    overflow.addDestination(dest, now, interactive);
                    overflowCount.incrementAndGet();
                }
            }
        }
    }

    private void runLogBatchWorker() {
        List<AegisDatabase.LogBatchItem> batch = new ArrayList<>(100);
        while (logBatchRunning || !isLogQueueEmpty()) {
            synchronized (logQueueLock) {
                while (logQueue.isEmpty() && overflowByUid.isEmpty() && logBatchRunning) {
                    try {
                        logQueueLock.wait();
                    } catch (InterruptedException e) {
                        // Interrupted on shutdown
                    }
                }
                if (logQueue.isEmpty() && overflowByUid.isEmpty()) {
                    break;
                }

                long firstItemTime = SystemClock.elapsedRealtime();
                while (logBatchRunning && logQueue.size() < 100 && overflowByUid.isEmpty()) {
                    long elapsed = SystemClock.elapsedRealtime() - firstItemTime;
                    if (elapsed >= 250L) {
                        break;
                    }
                    try {
                        logQueueLock.wait(250L - elapsed);
                    } catch (InterruptedException e) {
                        // Interrupted on shutdown
                        break;
                    }
                }

                for (int i = 0; i < 100 && !logQueue.isEmpty(); i++) {
                    AegisDatabase.LogBatchItem item = logQueue.poll();
                    if (item != null) {
                        batch.add(item);
                        UidDestKey key = getBatchItemKey(item);
                        if (pendingEntries.get(key) == item) {
                            pendingEntries.remove(key);
                        }
                    }
                }

                if (!overflowByUid.isEmpty() && batch.size() < 100) {
                    for (Iterator<Map.Entry<Integer, UidOverflow>> it = overflowByUid.entrySet().iterator(); it.hasNext(); ) {
                        if (batch.size() >= 100) {
                            break;
                        }
                        UidOverflow of = it.next().getValue();
                        it.remove();
                        Packet op = new Packet();
                        op.uid = of.uid;
                        op.time = of.lastTimestamp;
                        op.version = 4;
                        op.protocol = 6;
                        op.saddr = "";
                        op.sport = 0;
                        op.daddr = of.sampleDestinations.isEmpty() ? "overflow" : of.sampleDestinations.get(0);
                        op.dport = 0;
                        op.data = "overflow: +" + of.count + " dests [" + String.join(", ", of.sampleDestinations) + "]";
                        op.allowed = false;
                        batch.add(new AegisDatabase.LogBatchItem(op, null, of.count, of.interactive));
                    }
                }
            }

            if (!batch.isEmpty()) {
                try {
                    AegisDatabase.getInstance(this).insertBatch(batch);
                } catch (Throwable firstAttempt) {
                    Log.w(TAG, "insertBatch failed, retrying once", firstAttempt);
                    try {
                        AegisDatabase.getInstance(this).insertBatch(batch);
                    } catch (Throwable secondAttempt) {
                        Log.e(TAG, "insertBatch retry failed, items lost", secondAttempt);
                        lostCount.addAndGet(batch.size());
                    }
                }
                batch.clear();
            }

            checkLogStatsWarning();
        }
    }

    public void logPacket(Packet packet) {
        if (packet == null) return;
        enqueueLogItem(new AegisDatabase.LogBatchItem(packet, null, 0, isInteractive));
    }

    public void dnsResolved(ResourceRecord rr) {
        if (rr == null) {
            return;
        }

        enqueueLogItem(new AegisDatabase.LogBatchItem(rr));

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

        enqueueLogItem(new AegisDatabase.LogBatchItem(usage, null));
    }

    public void nativeExit(String reason) {
        Log.w(TAG, "nativeExit: " + reason);
        stop(false);
    }

    public void nativeError(int error, String message) {
        Log.e(TAG, "nativeError " + error + ": " + message);
    }
}
