package mv.aegis;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class FirewallRule {

	private static final String TAG = "Aegis.Rule";

	// Predefined defaults for known packages can be added later.
	private static final Map<String, Boolean> PREDEFINED_WIFI = new HashMap<>();
	private static final Map<String, Boolean> PREDEFINED_OTHER = new HashMap<>();
	private static final Map<String, Boolean> PREDEFINED_ROAMING = new HashMap<>();

	public int uid;
	public String packageName;
	public int icon;
	public String name;
	public String version;
	public boolean system;
	public boolean internet;
	public boolean enabled;
	public boolean pkg = true;

	public boolean wifi_default = false;
	public boolean other_default = false;
	public boolean screen_wifi_default = false;
	public boolean screen_other_default = false;
	public boolean roaming_default = false;

	public boolean wifi_blocked = false;
	public boolean other_blocked = false;
	public boolean screen_wifi = false;
	public boolean screen_other = false;
	public boolean roaming = false;
	public boolean lockdown = false;

	public boolean apply = true;
	public boolean notify = true;
	public boolean relateduids = false;
	public String[] related = null;
	public long hosts;
	public boolean changed;
	public boolean expanded = false;

	private static List<PackageInfo> cachePackageInfo = null;
	private static final Map<PackageInfo, String> cacheLabel = new HashMap<>();
	private static final Map<String, Boolean> cacheSystem = new HashMap<>();
	private static final Map<String, Boolean> cacheInternet = new HashMap<>();
	private static final Map<PackageInfo, Boolean> cacheEnabled = new HashMap<>();

	private static List<PackageInfo> getPackages(Context context) {
		if (cachePackageInfo == null) {
			PackageManager pm = context.getPackageManager();
			cachePackageInfo = pm.getInstalledPackages(0);
		}
		return new ArrayList<>(cachePackageInfo);
	}

	private static String getLabel(PackageInfo info, Context context) {
		String label = cacheLabel.get(info);
		if (label == null) {
			PackageManager pm = context.getPackageManager();
			label = info.applicationInfo.loadLabel(pm).toString();
			cacheLabel.put(info, label);
		}
		return label;
	}

	private static boolean isSystem(String packageName, Context context) {
		Boolean system = cacheSystem.get(packageName);
		if (system == null) {
			system = AegisUtils.isSystem(packageName, context);
			cacheSystem.put(packageName, system);
		}
		return system;
	}

	private static boolean hasInternet(String packageName, Context context) {
		Boolean internet = cacheInternet.get(packageName);
		if (internet == null) {
			internet = AegisUtils.hasInternet(packageName, context);
			cacheInternet.put(packageName, internet);
		}
		return internet;
	}

	private static boolean isEnabled(PackageInfo info, Context context) {
		Boolean enabled = cacheEnabled.get(info);
		if (enabled == null) {
			enabled = AegisUtils.isEnabled(info, context);
			cacheEnabled.put(info, enabled);
		}
		return enabled;
	}

	public static void clearCache(Context context) {
		synchronized (context.getApplicationContext()) {
			cachePackageInfo = null;
			cacheLabel.clear();
			cacheSystem.clear();
			cacheInternet.clear();
			cacheEnabled.clear();
		}

		AegisDatabase.getInstance(context).clearApps();
	}

	private FirewallRule(AegisDatabase db, PackageInfo info, Context context) {
		this.uid = info.applicationInfo.uid;
		this.packageName = info.packageName;
		this.icon = info.applicationInfo.icon;
		this.version = info.versionName;

		if (uid == 0) {
			name = "root";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else if (uid == 1013) {
			name = "Media Server";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else if (uid == 1020) {
			name = "MulticastDNSResponder";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else if (uid == 1021) {
			name = "GPS Daemon";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else if (uid == 1051) {
			name = "DNS Daemon";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else if (uid == 9999) {
			name = "Nobody";
			system = true;
			internet = true;
			enabled = true;
			pkg = false;
		} else {
			Cursor cursor = null;
			try {
				cursor = db.getApp(this.packageName);
				if (cursor != null && cursor.moveToFirst()) {
					name = cursor.getString(cursor.getColumnIndexOrThrow("label"));
					system = cursor.getInt(cursor.getColumnIndexOrThrow("system")) != 0;
					internet = cursor.getInt(cursor.getColumnIndexOrThrow("internet")) != 0;
					enabled = cursor.getInt(cursor.getColumnIndexOrThrow("enabled")) != 0;
				} else {
					name = getLabel(info, context);
					system = isSystem(this.packageName, context);
					internet = hasInternet(this.packageName, context);
					enabled = isEnabled(info, context);
					db.addApp(this.packageName, name, system, internet, enabled);
				}
			} finally {
				if (cursor != null) {
					cursor.close();
				}
			}
		}
	}

	public static List<FirewallRule> getRules(boolean all, Context context) {
		synchronized (context.getApplicationContext()) {
			Context appContext = context.getApplicationContext();
			SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(appContext);
			SharedPreferences wifi = appContext.getSharedPreferences("wifi", Context.MODE_PRIVATE);
			SharedPreferences other = appContext.getSharedPreferences("other", Context.MODE_PRIVATE);
			SharedPreferences screenWifi = appContext.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
			SharedPreferences screenOther = appContext.getSharedPreferences("screen_other", Context.MODE_PRIVATE);
			SharedPreferences roaming = appContext.getSharedPreferences("roaming", Context.MODE_PRIVATE);
			SharedPreferences lockdown = appContext.getSharedPreferences("lockdown", Context.MODE_PRIVATE);
			SharedPreferences apply = appContext.getSharedPreferences("apply", Context.MODE_PRIVATE);
			SharedPreferences notify = appContext.getSharedPreferences("notify", Context.MODE_PRIVATE);

			boolean defaultWifi = prefs.getBoolean("whitelist_wifi", true);
			boolean defaultOther = prefs.getBoolean("whitelist_other", true);
			boolean defaultScreenWifi = prefs.getBoolean("screen_wifi", false);
			boolean defaultScreenOther = prefs.getBoolean("screen_other", false);
			boolean defaultRoaming = prefs.getBoolean("whitelist_roaming", true);
			boolean manageSystem = prefs.getBoolean("manage_system", false);
			boolean screenOn = prefs.getBoolean("screen_on", true);
			boolean showUser = prefs.getBoolean("show_user", true);
			boolean showSystem = prefs.getBoolean("show_system", false);
			boolean showNointernet = prefs.getBoolean("show_nointernet", true);
			boolean showDisabled = prefs.getBoolean("show_disabled", true);
			defaultScreenWifi = defaultScreenWifi && screenOn;
			defaultScreenOther = defaultScreenOther && screenOn;

			AegisDatabase db = AegisDatabase.getInstance(appContext);
			List<PackageInfo> listPI = getPackages(appContext);
			Log.d("Aegis.Rule", "Installed packages visible: " + listPI.size() + ", all=" + all);

			int userId = Process.myUid() / 100000;

			PackageInfo root = new PackageInfo();
			root.applicationInfo = new ApplicationInfo();
			root.packageName = "root";
			root.applicationInfo.uid = 0;
			root.versionCode = Build.VERSION.SDK_INT;
			root.versionName = Build.VERSION.RELEASE;
			root.applicationInfo.icon = 0;
			listPI.add(root);

			PackageInfo media = new PackageInfo();
			media.applicationInfo = new ApplicationInfo();
			media.packageName = "android.media";
			media.applicationInfo.uid = 1013 + userId * 100000;
			media.versionCode = Build.VERSION.SDK_INT;
			media.versionName = Build.VERSION.RELEASE;
			media.applicationInfo.icon = 0;
			listPI.add(media);

			PackageInfo mdr = new PackageInfo();
			mdr.applicationInfo = new ApplicationInfo();
			mdr.packageName = "android.multicast";
			mdr.applicationInfo.uid = 1020 + userId * 100000;
			mdr.versionCode = Build.VERSION.SDK_INT;
			mdr.versionName = Build.VERSION.RELEASE;
			mdr.applicationInfo.icon = 0;
			listPI.add(mdr);

			PackageInfo gps = new PackageInfo();
			gps.applicationInfo = new ApplicationInfo();
			gps.packageName = "android.gps";
			gps.applicationInfo.uid = 1021 + userId * 100000;
			gps.versionCode = Build.VERSION.SDK_INT;
			gps.versionName = Build.VERSION.RELEASE;
			gps.applicationInfo.icon = 0;
			listPI.add(gps);

			PackageInfo dns = new PackageInfo();
			dns.applicationInfo = new ApplicationInfo();
			dns.packageName = "android.dns";
			dns.applicationInfo.uid = 1051 + userId * 100000;
			dns.versionCode = Build.VERSION.SDK_INT;
			dns.versionName = Build.VERSION.RELEASE;
			dns.applicationInfo.icon = 0;
			listPI.add(dns);

			PackageInfo nobody = new PackageInfo();
			nobody.applicationInfo = new ApplicationInfo();
			nobody.packageName = "nobody";
			nobody.applicationInfo.uid = 9999;
			nobody.versionCode = Build.VERSION.SDK_INT;
			nobody.versionName = Build.VERSION.RELEASE;
			nobody.applicationInfo.icon = 0;
			listPI.add(nobody);

			List<FirewallRule> listRules = new ArrayList<>();

			for (PackageInfo info : listPI) {
				try {
					if (info.applicationInfo.uid == Process.myUid()) {
						continue;
					}

					FirewallRule rule = new FirewallRule(db, info, appContext);
					if (all || ((rule.system ? showSystem : showUser)
							&& (showNointernet || rule.internet)
							&& (showDisabled || rule.enabled))) {

						rule.wifi_default = PREDEFINED_WIFI.containsKey(info.packageName)
								? PREDEFINED_WIFI.get(info.packageName)
								: defaultWifi;
						rule.other_default = PREDEFINED_OTHER.containsKey(info.packageName)
								? PREDEFINED_OTHER.get(info.packageName)
								: defaultOther;
						rule.screen_wifi_default = defaultScreenWifi;
						rule.screen_other_default = defaultScreenOther;
						rule.roaming_default = PREDEFINED_ROAMING.containsKey(info.packageName)
								? PREDEFINED_ROAMING.get(info.packageName)
								: defaultRoaming;

						rule.wifi_blocked = (!(rule.system && !manageSystem)
								&& wifi.getBoolean(info.packageName, rule.wifi_default));
						rule.other_blocked = (!(rule.system && !manageSystem)
								&& other.getBoolean(info.packageName, rule.other_default));
						rule.screen_wifi = screenWifi.getBoolean(info.packageName, rule.screen_wifi_default) && screenOn;
						rule.screen_other = screenOther.getBoolean(info.packageName, rule.screen_other_default) && screenOn;
						rule.roaming = roaming.getBoolean(info.packageName, rule.roaming_default);
						rule.lockdown = lockdown.getBoolean(info.packageName, false);
						rule.apply = apply.getBoolean(info.packageName, true);
						rule.notify = notify.getBoolean(info.packageName, true);

						List<String> listPkg = new ArrayList<>();
						for (PackageInfo related : listPI) {
							if (related.applicationInfo.uid == rule.uid && !related.packageName.equals(rule.packageName)) {
								rule.relateduids = true;
								listPkg.add(related.packageName);
							}
						}
						rule.related = listPkg.toArray(new String[0]);
						rule.hosts = db.getHostCount(rule.uid, true);
						rule.updateChanged(defaultWifi, defaultOther, defaultRoaming);
						listRules.add(rule);
					}
				} catch (Throwable ex) {
					Log.e("Aegis.Rule", "Error processing package " + info.packageName + ": " + ex.getMessage(), ex);
				}
			}

			String sort = prefs.getString("sort", "name");
			if ("uid".equals(sort)) {
				Collator collator = Collator.getInstance(Locale.getDefault());
				Collections.sort(listRules, (a, b) -> {
					int byUid = Integer.compare(a.uid, b.uid);
					if (byUid != 0) {
						return byUid;
					}
					return collator.compare(a.name, b.name);
				});
			} else {
				final Collator collator = Collator.getInstance(Locale.getDefault());
				collator.setStrength(Collator.SECONDARY);
				Collections.sort(listRules, new Comparator<FirewallRule>() {
					@Override
					public int compare(FirewallRule left, FirewallRule right) {
						if (!all && left.changed != right.changed) {
							return left.changed ? -1 : 1;
						}
						return collator.compare(left.name, right.name);
					}
				});
			}

			Log.d("Aegis.Rule", "getRules returning " + listRules.size() + " rules, all=" + all);
			return listRules;
		}
	}

	public static void updateRule(Context context, FirewallRule rule) {
		Context appContext = context.getApplicationContext();
		appContext.getSharedPreferences("wifi", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.wifi_blocked)
				.apply();

		appContext.getSharedPreferences("other", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.other_blocked)
				.apply();

		appContext.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.screen_wifi)
				.apply();

		appContext.getSharedPreferences("screen_other", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.screen_other)
				.apply();

		appContext.getSharedPreferences("roaming", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.roaming)
				.apply();

		appContext.getSharedPreferences("lockdown", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.lockdown)
				.apply();

		appContext.getSharedPreferences("apply", Context.MODE_PRIVATE)
				.edit()
				.putBoolean(rule.packageName, rule.apply)
				.apply();
	}

	private void updateChanged(boolean defaultWifi, boolean defaultOther, boolean defaultRoaming) {
		changed = (wifi_blocked != defaultWifi
				|| other_blocked != defaultOther
				|| (wifi_blocked && screen_wifi != screen_wifi_default)
				|| (other_blocked && screen_other != screen_other_default)
				|| ((!other_blocked || screen_other) && roaming != defaultRoaming)
				|| hosts > 0
				|| lockdown
				|| !apply);
	}

	public void updateChanged(Context context) {
		SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context.getApplicationContext());
		boolean screenOn = prefs.getBoolean("screen_on", true);
		boolean defaultWifi = prefs.getBoolean("whitelist_wifi", true);
		boolean defaultOther = prefs.getBoolean("whitelist_other", true);
		boolean defaultRoaming = prefs.getBoolean("whitelist_roaming", true);

		screen_wifi_default = prefs.getBoolean("screen_wifi", false) && screenOn;
		screen_other_default = prefs.getBoolean("screen_other", false) && screenOn;
		updateChanged(defaultWifi, defaultOther, defaultRoaming);
	}

	@Override
	public String toString() {
		return this.name;
	}
}

