package mv.aegis;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.MenuItem;
import android.widget.ImageButton;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import com.mv.aegis.R;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SettingsActivity extends BaseActivity implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static final String TAG = "Aegis.Settings";
    private boolean running = false;

    private static final Set<String> RELOAD_KEYS = new HashSet<>(Arrays.asList(
            "filter", "log", "whitelist_wifi", "whitelist_other", "whitelist_roaming",
            "screen_wifi", "screen_other", "screen_on", "subnet", "tethering", "lan", "ip6",
            "manage_system", "lockdown_wifi", "lockdown_other", "use_metered", "dns", "dns2",
            "vpn4", "vpn6", "use_hosts", "track_usage"
    ));

	@Override
	protected void onCreate(@Nullable Bundle savedInstanceState) {
		AegisUtils.setTheme(this);
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_settings);
        setupBottomNav();
		running = true;

		ImageButton ibBack = findViewById(R.id.ibBack);
		ibBack.setOnClickListener(v -> finish());

		if (getSupportActionBar() != null) {
			getSupportActionBar().hide();
		}

		if (savedInstanceState == null) {
			getSupportFragmentManager()
					.beginTransaction()
					.replace(R.id.settings_container, new FragmentSettings())
					.commit();
		}

		PreferenceManager.getDefaultSharedPreferences(this)
				.registerOnSharedPreferenceChangeListener(this);
	}

	@Override
	public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
		if (!running) {
			return;
		}

		if ("theme_mode".equals(name) || "theme".equals(name) || "dark_theme".equals(name)) {
			AegisUtils.applyNightMode(this);
			recreate();
		} else if (RELOAD_KEYS.contains(name)) {
			FirewallService.reload("changed " + name, this, false);
		} else if ("log_app".equals(name)) {
			Intent changedIntent = new Intent(HomeActivity.ACTION_RULES_CHANGED);
			LocalBroadcastManager.getInstance(this).sendBroadcast(changedIntent);
			FirewallService.reload("changed " + name, this, false);
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		if (item.getItemId() == android.R.id.home) {
			finish();
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	@Override
	protected void onDestroy() {
		running = false;
		PreferenceManager.getDefaultSharedPreferences(this)
				.unregisterOnSharedPreferenceChangeListener(this);
		super.onDestroy();
	}
}
