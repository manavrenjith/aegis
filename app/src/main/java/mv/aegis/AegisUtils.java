package mv.aegis;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.PowerManager;
import android.text.TextUtils;
import android.util.Log;

import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.app.ActivityCompat;
import androidx.core.net.ConnectivityManagerCompat;
import androidx.preference.PreferenceManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AegisUtils {

    private static final String TAG = "Aegis.Utils";

    private AegisUtils() {
    }

    public static boolean isSystem(String packageName, Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(packageName, 0);
            return ((info.applicationInfo.flags &
                    (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0);
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    public static boolean isSystem(int uid, Context context) {
        PackageManager pm = context.getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null) {
            for (String pkg : packages) {
                if (isSystem(pkg, context)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean hasInternet(String packageName, Context context) {
        PackageManager pm = context.getPackageManager();
        return (pm.checkPermission("android.permission.INTERNET", packageName)
                == PackageManager.PERMISSION_GRANTED);
    }

    public static boolean hasInternet(int uid, Context context) {
        PackageManager pm = context.getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null) {
            for (String pkg : packages) {
                if (hasInternet(pkg, context)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isEnabled(PackageInfo info, Context context) {
        int setting;
        try {
            PackageManager pm = context.getPackageManager();
            setting = pm.getApplicationEnabledSetting(info.packageName);
        } catch (IllegalArgumentException ex) {
            setting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
        }

        if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT) {
            return info.applicationInfo.enabled;
        } else {
            return (setting == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
        }
    }

    @SuppressLint({"MissingPermission", "Deprecated"})
    public static boolean isConnected(Context context) {
        ConnectivityManager cm =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return false;
        }

        NetworkInfo active = cm.getActiveNetworkInfo();
        if (active != null && active.isConnected()) {
            return true;
        }

        Network[] networks = cm.getAllNetworks();
        for (Network network : networks) {
            NetworkInfo info = cm.getNetworkInfo(network);
            if (info != null && info.getType() != ConnectivityManager.TYPE_VPN && info.isConnected()) {
                return true;
            }
        }

        return false;
    }

    @SuppressLint("MissingPermission")
    public static boolean isMeteredNetwork(Context context) {
        ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        return (cm != null && ConnectivityManagerCompat.isActiveNetworkMetered(cm));
    }

    @SuppressLint("Deprecated")
    public static boolean isInteractive(Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT_WATCH) {
            return (pm != null && pm.isScreenOn());
        } else {
            return (pm != null && pm.isInteractive());
        }
    }

    @SuppressLint({"MissingPermission", "Deprecated"})
    public static boolean isWifiActive(Context context) {
        ConnectivityManager cm =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return false;
        }

        NetworkInfo active = cm.getActiveNetworkInfo();
        return (active != null && active.getType() == ConnectivityManager.TYPE_WIFI);
    }

    public static List<String> getApplicationNames(int uid, Context context) {
        List<String> names = new ArrayList<>();

        if (uid == 0) {
            names.add("Root");
            return names;
        }

        if (uid == 1013) {
            names.add("Media Server");
            return names;
        }

        if (uid == 9999) {
            names.add("Nobody");
            return names;
        }

        PackageManager pm = context.getPackageManager();
        try {
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null) {
                for (String pkg : packages) {
                    ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                    CharSequence label = pm.getApplicationLabel(info);
                    if (label != null) {
                        String text = label.toString();
                        if (!TextUtils.isEmpty(text)) {
                            names.add(text);
                        }
                    }
                }
            }
        } catch (SecurityException ex) {
            names.add("UID:" + uid);
        } catch (PackageManager.NameNotFoundException ignored) {
            // Ignore missing package names and keep available labels.
        }

        Collections.sort(names);
        return names;
    }

    public static void setTheme(Context context) {
        // Theme applied via AppCompatDelegate and values-night/ resources
    }

    public static void applyNightMode(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if (!prefs.contains("theme_mode")) {
            boolean dark = prefs.getBoolean("dark_theme", false);
            prefs.edit()
                    .putString("theme_mode", dark ? "2" : "-1")
                    .remove("dark_theme")
                    .remove("theme")
                    .apply();
        }

        String modeStr = prefs.getString("theme_mode", "-1");
        int mode;
        if ("1".equals(modeStr)) {
            mode = AppCompatDelegate.MODE_NIGHT_NO;
        } else if ("2".equals(modeStr)) {
            mode = AppCompatDelegate.MODE_NIGHT_YES;
        } else {
            mode = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM;
        }

        AppCompatDelegate.setDefaultNightMode(mode);
    }

    public static boolean canNotify(Context context) {
        if (Build.VERSION.SDK_INT < 33) {
            return true;
        }

        return ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED;
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format(Locale.US, "%.1f KB", bytes / 1024f);
        } else if (bytes < 1024L * 1024L * 1024L) {
            return String.format(Locale.US, "%.1f MB", bytes / (1024f * 1024f));
        } else {
            return String.format(Locale.US, "%.2f GB", bytes / (1024f * 1024f * 1024f));
        }
    }

    public static int dips2pixels(int dips, Context context) {
        return Math.round(dips * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static String getProtocolName(int protocol, int version, boolean brief) {
        String p;
        String b;

        switch (protocol) {
            case 1:
            case 58:
                p = "ICMP";
                b = "I";
                break;
            case 6:
                p = "TCP";
                b = "T";
                break;
            case 17:
                p = "UDP";
                b = "U";
                break;
            case 2:
                p = "IGMP";
                b = "G";
                break;
            case 50:
                p = "ESP";
                b = "E";
                break;
            default:
                return protocol + "/" + version;
        }

        return (brief ? b : p) + (version > 0 ? version : "");
    }

    public static void logExtras(Intent intent) {
        if (intent == null) {
            return;
        }

        android.os.Bundle extras = intent.getExtras();
        if (extras == null) {
            return;
        }

        Set<String> keys = extras.keySet();
        for (String key : keys) {
            Object value = extras.get(key);
            Log.d(TAG, key + "=" + String.valueOf(value));
        }
    }
}
