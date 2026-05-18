package mv.aegis;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
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

    private static final String TAG = "FirewallService";
    private static final String CHANNEL_ID_FOREGROUND = "foreground";

    private enum State {
        none,
        waiting,
        enforcing
    }

    private State state = State.none;
    private ParcelFileDescriptor vpn = null;
    private boolean temporarilyStopped = false;
    private volatile Looper commandLooper;
    private volatile CommandHandler commandHandler;
    private static Object jni_lock = new Object();
    private static long jni_context = 0;
    private Thread tunnelThread = null;

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

        vpn = builder.establish();
        if (vpn == null) {
            throw new IllegalStateException("VPN establish failed");
        }

        // Log rules before passing to native layer
        java.util.List<FirewallRule> rules = FirewallRule.getRules(false, this);
        Log.d(TAG, "start() - Loaded " + rules.size() + " firewall rules from getRules()");
        for (FirewallRule rule : rules) {
            Log.d(TAG, "  Rule: " + rule.packageName + " uid=" + rule.uid + " wifi_blocked=" + rule.wifi_blocked + " other_blocked=" + rule.other_blocked);
        }

        // TODO: jni_start(jni_context, loglevel)
        // TODO: Pass rules to native layer here - jni_add_rule() for each rule or jni_set_rules(array)

        if (tunnelThread != null && tunnelThread.isAlive()) {
            return;
        }

        tunnelThread = new Thread(() -> {
            // TODO: jni_run(jni_context, vpn.getFd(), false, 3)
        }, "FirewallTunnel");
        tunnelThread.start();
    }

    private void reload(boolean interactive) {
        if (state != State.enforcing) {
            stopForeground(true);
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification());
            state = State.enforcing;
        }

        if (vpn != null) {
            try {
                vpn.close();
            } catch (Exception exception) {
                Log.w(TAG, "Failed to close VPN on reload", exception);
            }
            vpn = null;

            try {
                Thread.sleep(500L);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
            }
        }

        Log.d(TAG, "reload() - Reloading firewall rules");
        start();
    }

    private void stop(boolean temporary) {
        if (vpn != null) {
            // TODO: jni_stop(jni_context)
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

        state = State.waiting;
        startForeground(NOTIFY_WAITING, getWaitingNotification());

        synchronized (jni_lock) {
            jni_context = jni_init(Build.VERSION.SDK_INT);
        }

        HandlerThread handlerThread = new HandlerThread("AegisCommand", android.os.Process.THREAD_PRIORITY_FOREGROUND);
        handlerThread.start();
        commandLooper = handlerThread.getLooper();
        commandHandler = new CommandHandler(commandLooper);
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
}

