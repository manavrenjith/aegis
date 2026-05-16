package mv.aegis;

import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

import com.mv.aegis.R;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AppDetailActivity extends AppCompatActivity {

    public static final String EXTRA_UID = "uid";
    public static final String EXTRA_PACKAGE = "package";
    private static final String TAG = "Aegis.AppDetail";
    private static final long REFRESH_INTERVAL_MS = 3000L;

    private int uid;
    private String packageName;
    private FirewallRule rule = null;
    private AdapterAccess adapterAccess = null;
    private boolean running = false;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            if (running) {
                refreshAccess();
                handler.postDelayed(this, REFRESH_INTERVAL_MS);
            }
        }
    };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_detail);
        running = true;

        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.hide();
        }

        uid = getIntent().getIntExtra(EXTRA_UID, -1);
        packageName = getIntent().getStringExtra(EXTRA_PACKAGE);

        ImageButton ibBack = findViewById(R.id.ibBack);
        ibBack.setOnClickListener(v -> finish());

        loadRule();
        setupAccessList();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS);
        refreshAccess();
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refreshRunnable);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        running = false;
        executor.shutdown();
        if (adapterAccess != null) {
            adapterAccess.changeCursor(null);
        }
        super.onDestroy();
    }

    private void loadRule() {
        executor.execute(() -> {
            FirewallRule foundRule = null;
            try {
                List<FirewallRule> rules = FirewallRule.getRules(false, this);
                for (FirewallRule firewallRule : rules) {
                    if (firewallRule.uid == uid) {
                        foundRule = firewallRule;
                        break;
                    }
                }

                FirewallRule finalFoundRule = foundRule;
                handler.post(() -> {
                    rule = finalFoundRule;
                    bindRuleToUI();
                });
            } catch (Throwable throwable) {
                Log.e(TAG, "Failed to load app rule", throwable);
            }
        });
    }

    private void bindRuleToUI() {
        TextView tvAppName = findViewById(R.id.tvAppName);
        tvAppName.setText(rule != null ? rule.name : "Unknown");

        TextView tvPackageName = findViewById(R.id.tvPackageName);
        tvPackageName.setText(packageName == null ? "" : packageName);

        ImageView ivAppIcon = findViewById(R.id.ivAppIcon);
        final String iconPackage = packageName;
        executor.execute(() -> {
            Drawable drawable;
            try {
                drawable = getPackageManager().getApplicationIcon(iconPackage);
            } catch (Throwable ignored) {
                drawable = getPackageManager().getDefaultActivityIcon();
            }

            Drawable finalDrawable = drawable;
            ivAppIcon.post(() -> ivAppIcon.setImageDrawable(finalDrawable));
        });

        TextView tvUid = findViewById(R.id.tvUid);
        tvUid.setText("UID: " + uid);

        TextView tvVersion = findViewById(R.id.tvVersion);
        tvVersion.setText(rule != null && rule.version != null ? "v" + rule.version : "");

        TextView tvSystem = findViewById(R.id.tvSystem);
        tvSystem.setVisibility(rule != null && rule.system ? View.VISIBLE : View.GONE);

        TextView tvNoInternet = findViewById(R.id.tvNoInternet);
        tvNoInternet.setVisibility(rule != null && !rule.internet ? View.VISIBLE : View.GONE);

        ImageButton ibWifi = findViewById(R.id.ibWifi);
        if (rule != null && rule.wifi_blocked) {
            ibWifi.setImageResource(R.drawable.wifi_off);
        } else {
            ibWifi.setImageResource(R.drawable.wifi_on);
        }
        ibWifi.setOnClickListener(v -> {
            if (rule == null) {
                return;
            }
            rule.wifi_blocked = !rule.wifi_blocked;
            ibWifi.setImageResource(rule.wifi_blocked ? R.drawable.wifi_off : R.drawable.wifi_on);
            FirewallRule.updateRule(this, rule);
            FirewallService.reload("wifi", this, false);
        });

        ImageButton ibOther = findViewById(R.id.ibOther);
        if (rule != null && rule.other_blocked) {
            ibOther.setImageResource(R.drawable.other_off);
        } else {
            ibOther.setImageResource(R.drawable.other_on);
        }
        ibOther.setOnClickListener(v -> {
            if (rule == null) {
                return;
            }
            rule.other_blocked = !rule.other_blocked;
            ibOther.setImageResource(rule.other_blocked ? R.drawable.other_off : R.drawable.other_on);
            FirewallRule.updateRule(this, rule);
            FirewallService.reload("other", this, false);
        });

        TextView tvTotalSent = findViewById(R.id.tvTotalSent);
        TextView tvTotalReceived = findViewById(R.id.tvTotalReceived);
        tvTotalSent.setText(AegisUtils.formatBytes(0));
        tvTotalReceived.setText(AegisUtils.formatBytes(0));

        refreshUsage();
    }

    private void refreshUsage() {
        executor.execute(() -> {
            long sent = 0L;
            long received = 0L;
            Cursor cursor = null;
            try {
                cursor = AegisDatabase.getInstance(this).getUsageByApp();
                int colUid = cursor.getColumnIndex("uid");
                int colSent = cursor.getColumnIndex("total_sent");
                int colReceived = cursor.getColumnIndex("total_received");

                while (cursor.moveToNext()) {
                    if (colUid >= 0 && cursor.getInt(colUid) == uid) {
                        sent = colSent >= 0 ? cursor.getLong(colSent) : 0L;
                        received = colReceived >= 0 ? cursor.getLong(colReceived) : 0L;
                        break;
                    }
                }

                long finalSent = sent;
                long finalReceived = received;
                handler.post(() -> {
                    TextView tvTotalSent = findViewById(R.id.tvTotalSent);
                    TextView tvTotalReceived = findViewById(R.id.tvTotalReceived);
                    tvTotalSent.setText(AegisUtils.formatBytes(finalSent));
                    tvTotalReceived.setText(AegisUtils.formatBytes(finalReceived));
                });
            } catch (Throwable throwable) {
                Log.e(TAG, "Failed to refresh usage", throwable);
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        });
    }

    private void setupAccessList() {
        android.widget.ListView lvAccess = findViewById(R.id.lvAccess);
        Cursor cursor = AegisDatabase.getInstance(this).getAccess(uid);
        adapterAccess = new AdapterAccess(this, cursor);
        lvAccess.setAdapter(adapterAccess);
    }

    private void refreshAccess() {
        try {
            Cursor cursor = AegisDatabase.getInstance(this).getAccess(uid);
            if (adapterAccess != null) {
                adapterAccess.changeCursor(cursor);
            }
            refreshUsage();
        } catch (Throwable throwable) {
            Log.e(TAG, "Failed to refresh access", throwable);
        }
    }
}

