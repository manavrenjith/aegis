package mv.aegis;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.chip.Chip;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.mv.aegis.R;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HomeActivity extends BaseActivity {

    public static final String ACTION_RULES_CHANGED = "mv.aegis.RULES_CHANGED";
    public static final String ACTION_QUEUE_CHANGED = "mv.aegis.QUEUE_CHANGED";
    public static final String EXTRA_REFRESH = "Refresh";
    public static final String EXTRA_SEARCH = "Search";
    public static final String EXTRA_CONNECTED = "Connected";
    public static final String EXTRA_METERED = "Metered";
    public static final String EXTRA_SIZE = "Size";
    private static final int REQUEST_VPN = 1;

    private boolean running = false;
    private SwipeRefreshLayout swipeRefresh = null;
    private ExecutorService executor = Executors.newSingleThreadExecutor();
    private Handler handler = new Handler(Looper.getMainLooper());
    private AdapterRule adapter = null;

    private final BroadcastReceiver onRulesChanged = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (ACTION_RULES_CHANGED.equals(intent.getAction())) {
                updateApplicationList(null);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        setupBottomNav();
        running = true;

        boolean enabled = PreferenceManager.getDefaultSharedPreferences(this)
                .getBoolean("enabled", false);

        MaterialSwitch swEnabled = findViewById(R.id.swEnabled);
        swEnabled.setChecked(enabled);
        configureEnabledSwitch(swEnabled);

        updateHeroCard(enabled);

        RecyclerView rvApplication = findViewById(R.id.rvApplication);
        rvApplication.setHasFixedSize(false);
        rvApplication.setLayoutManager(new LinearLayoutManager(this));
        adapter = new AdapterRule(this);
        rvApplication.setAdapter(adapter);

        Chip chipAll = findViewById(R.id.chipAll);
        Chip chipBlocked = findViewById(R.id.chipBlocked);
        Chip chipWifiOnly = findViewById(R.id.chipWifiOnly);
        Chip chipDataOnly = findViewById(R.id.chipDataOnly);
        Chip chipAllowed = findViewById(R.id.chipAllowed);

        chipAll.setOnClickListener(v -> {
            setActiveChip(chipAll, chipBlocked, chipWifiOnly, chipDataOnly, chipAllowed);
            if (adapter != null) {
                adapter.filter(null);
            }
        });
        chipBlocked.setOnClickListener(v -> {
            setActiveChip(chipBlocked, chipAll, chipWifiOnly, chipDataOnly, chipAllowed);
            if (adapter != null) {
                adapter.filter("blocked");
            }
        });
        chipWifiOnly.setOnClickListener(v -> {
            setActiveChip(chipWifiOnly, chipAll, chipBlocked, chipDataOnly, chipAllowed);
            if (adapter != null) {
                adapter.filter("wifi");
            }
        });
        chipDataOnly.setOnClickListener(v -> {
            setActiveChip(chipDataOnly, chipAll, chipBlocked, chipWifiOnly, chipAllowed);
            if (adapter != null) {
                adapter.filter("data");
            }
        });
        chipAllowed.setOnClickListener(v -> {
            setActiveChip(chipAllowed, chipAll, chipBlocked, chipWifiOnly, chipDataOnly);
            if (adapter != null) {
                adapter.filter("allowed");
            }
        });

        TextView tvSeeAll = findViewById(R.id.tvSeeAll);
        if (tvSeeAll != null) {
            tvSeeAll.setOnClickListener(v -> {
                if (adapter != null) {
                    adapter.filter(null);
                }
                setActiveChip(chipAll, chipBlocked, chipWifiOnly, chipDataOnly, chipAllowed);
            });
        }

        setActiveChip(chipAll, chipBlocked, chipWifiOnly, chipDataOnly, chipAllowed);

        LinearLayout tabHome = findViewById(R.id.tabHome);
        LinearLayout tabActivity = findViewById(R.id.tabActivity);
        LinearLayout tabLog = findViewById(R.id.tabLog);
        LinearLayout tabSettings = findViewById(R.id.tabSettings);

        tabHome.setOnClickListener(view -> {
            // Already on home.
        });
        tabActivity.setOnClickListener(view -> startActivity(new Intent(this, AppListActivity.class)));
        tabLog.setOnClickListener(view -> startActivity(new Intent(this, LogActivity.class)));
        tabSettings.setOnClickListener(view -> startActivity(new Intent(this, SettingsActivity.class)));

        TextView tvDisabled = findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);

        TextView tvNotifications = findViewById(R.id.tvNotifications);
        tvNotifications.setVisibility(View.GONE);

        swipeRefresh = findViewById(R.id.swipeRefresh);
        swipeRefresh.setOnRefreshListener(() -> {
            updateApplicationList(null);
            swipeRefresh.setRefreshing(false);
        });

        updateApplicationList(null);
    }

    private void setActiveChip(Chip active, Chip... inactive) {
        active.setChecked(true);
        for (Chip chip : inactive) {
            chip.setChecked(false);
        }
    }

    private void configureEnabledSwitch(MaterialSwitch swEnabled) {
        swEnabled.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                try {
                    Intent prepare = VpnService.prepare(this);
                    if (prepare == null) {
                        onActivityResult(REQUEST_VPN, RESULT_OK, null);
                    } else {
                        startActivityForResult(prepare, REQUEST_VPN);
                    }
                } catch (Throwable throwable) {
                    Log.e("HomeActivity", "Failed to request VPN permission", throwable);
                }
            } else {
                PreferenceManager.getDefaultSharedPreferences(this)
                        .edit()
                        .putBoolean("enabled", false)
                        .apply();
                FirewallService.stop("switch off", this, false);
            }
            updateHeroCard(isChecked);
        });
    }

    private void updateApplicationList(@Nullable String search) {
        executor.execute(() -> {
            List<FirewallRule> rules = Collections.emptyList();
            try {
                rules = FirewallRule.getRules(false, this);
                Log.d("Aegis.Main", "Rules loaded: " + rules.size());
                if (rules.isEmpty()) {
                    Log.w("Aegis.Main", "No rules returned — check FirewallRule.getRules()");
                }
            } catch (Throwable throwable) {
                Log.e("HomeActivity", "Failed to load firewall rules", throwable);
            }

            List<FirewallRule> finalRules = rules;
            handler.post(() -> {
                if (adapter != null) {
                    adapter.set(finalRules);
                    if (search != null) {
                        adapter.getFilter().filter(search);
                    }
                }
                if (swipeRefresh != null) {
                    swipeRefresh.setRefreshing(false);
                }
                updateStatCards();
            });
        });
    }

    private void updateStatCards() {
        android.content.SharedPreferences wifi = getSharedPreferences("wifi", MODE_PRIVATE);
        android.content.SharedPreferences other = getSharedPreferences("other", MODE_PRIVATE);

        Set<String> keys = new HashSet<>();
        keys.addAll(wifi.getAll().keySet());
        keys.addAll(other.getAll().keySet());

        int blocked = 0;
        for (String key : keys) {
            if (wifi.getBoolean(key, false) || other.getBoolean(key, false)) {
                blocked++;
            }
        }

        TextView tvAppsBlocked = findViewById(R.id.tvAppsBlocked);
        tvAppsBlocked.setText(String.valueOf(blocked));

        TextView tvDataToday = findViewById(R.id.tvDataToday);
        tvDataToday.setText("0 B"); // TODO: wire AegisDatabase.getTodayUsage()
    }

    private void updateHeroCard(boolean enabled) {
        TextView tvStatusBadge = findViewById(R.id.tvStatusBadge);
        TextView tvStatusTitle = findViewById(R.id.tvStatusTitle);
        TextView tvStatusSubtitle = findViewById(R.id.tvStatusSubtitle);
        TextView tvDisabled = findViewById(R.id.tvDisabled);

        if (enabled) {
            tvStatusBadge.setText("\u25cf Active");
            tvStatusBadge.setTextColor(ContextCompat.getColor(this, R.color.color_on));
            tvStatusTitle.setText("Protected");
            tvStatusSubtitle.setText("All network traffic is being filtered");
            tvDisabled.setVisibility(View.GONE);
        } else {
            tvStatusBadge.setText("\u25cf Inactive");
            tvStatusBadge.setTextColor(ContextCompat.getColor(this, R.color.color_off));
            tvStatusTitle.setText("Unprotected");
            tvStatusSubtitle.setText("Traffic is not being filtered");
            tvDisabled.setVisibility(View.VISIBLE);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_VPN) {
            MaterialSwitch swEnabled = findViewById(R.id.swEnabled);
            if (resultCode == RESULT_OK) {
                PreferenceManager.getDefaultSharedPreferences(this)
                        .edit()
                        .putBoolean("enabled", true)
                        .apply();
                FirewallService.start("prepare", this);
                FirewallService.reload("enabled", this, false);
            } else {
                PreferenceManager.getDefaultSharedPreferences(this)
                        .edit()
                        .putBoolean("enabled", false)
                        .apply();
                swEnabled.setOnCheckedChangeListener(null);
                swEnabled.setChecked(false);
                configureEnabledSwitch(swEnabled);
                updateHeroCard(false);
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        LocalBroadcastManager.getInstance(this)
                .registerReceiver(onRulesChanged, new IntentFilter(ACTION_RULES_CHANGED));
        updateStatCards();
    }

    @Override
    protected void onPause() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(onRulesChanged);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        running = false;
        executor.shutdown();
        super.onDestroy();
    }
}
