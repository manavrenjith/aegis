package mv.aegis;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.mv.aegis.R;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LogActivity extends BaseActivity {

    private static final String TAG = "Aegis.Log";
    private static final long REFRESH_INTERVAL_MS = 2000L;

    private AdapterLog adapter;
    private RecyclerView rvLog;
    private TextView tvDisabled;
    private boolean filterShowUnknown = true;
    private boolean filterShowAllowed = true;
    private boolean filterShowBlocked = true;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final AegisDatabase.LogChangedListener logChangedListener = this::scheduleRefresh;

    private final BroadcastReceiver rulesReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            scheduleRefresh();
        }
    };

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            refreshLog();
            handler.postDelayed(this, REFRESH_INTERVAL_MS);
        }
    };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logging);
        setupBottomNav();
        com.google.android.material.bottomnavigation.BottomNavigationView bottomNav = findViewById(R.id.bottomNav);
        if (bottomNav != null) {
            bottomNav.setSelectedItemId(R.id.nav_log);
        }

        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.hide();
        }

        tvDisabled = findViewById(R.id.tvDisabled);
        rvLog = findViewById(R.id.rvLog);
        rvLog.setLayoutManager(new LinearLayoutManager(this));

        adapter = new AdapterLog(this);
        rvLog.setAdapter(adapter);

        ImageButton ibClearLog = findViewById(R.id.ibClearLog);
        ibClearLog.setOnClickListener(v -> clearLog());

        ImageButton ibLogOptions = findViewById(R.id.ibLogOptions);
        ibLogOptions.setOnClickListener(v -> showFilterDialog());

        updateDisabledBanner();
        refreshLog();
    }

    @Override
    protected void onResume() {
        super.onResume();
        AegisDatabase.getInstance(this).addLogChangedListener(logChangedListener);
        LocalBroadcastManager.getInstance(this)
                .registerReceiver(rulesReceiver, new IntentFilter(HomeActivity.ACTION_RULES_CHANGED));
        handler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS);
        refreshLog();
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refreshRunnable);
        AegisDatabase.getInstance(this).removeLogChangedListener(logChangedListener);
        LocalBroadcastManager.getInstance(this).unregisterReceiver(rulesReceiver);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void updateDisabledBanner() {
        boolean enabled = PreferenceManager.getDefaultSharedPreferences(this)
                .getBoolean("log_app", true);
        tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);
    }

    private void scheduleRefresh() {
        handler.post(this::refreshLog);
    }

    private void refreshLog() {
        updateDisabledBanner();
        executor.execute(() -> {
            Cursor cursor = null;
            try {
                cursor = AegisDatabase.getInstance(this).getLog(
                        true,
                        true,
                        true,
                        filterShowAllowed,
                        filterShowBlocked,
                        filterShowUnknown
                );

                final Cursor result = cursor;
                handler.post(() -> {
                    adapter.swapCursor(result);
                    if (adapter.getItemCount() > 0) {
                        rvLog.scrollToPosition(0);
                    }
                });
            } catch (Throwable throwable) {
                if (cursor != null) {
                    cursor.close();
                }
                Log.e(TAG, "Failed to refresh log", throwable);
            }
        });
    }

    private void clearLog() {
        new MaterialAlertDialogBuilder(this)
                .setTitle("Clear log")
                .setMessage("Delete all log entries?")
                .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                    AegisDatabase.getInstance(this).clearLog(-1);
                    refreshLog();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void showFilterDialog() {
        View content = getLayoutInflater().inflate(R.layout.dialog_log_filter, null, false);

        CheckBox cbFilterUnknown = content.findViewById(R.id.cbFilterUnknown);
        CheckBox cbFilterAllowed = content.findViewById(R.id.cbFilterAllowed);
        CheckBox cbFilterBlocked = content.findViewById(R.id.cbFilterBlocked);

        cbFilterUnknown.setChecked(filterShowUnknown);
        cbFilterAllowed.setChecked(filterShowAllowed);
        cbFilterBlocked.setChecked(filterShowBlocked);

        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.menu_filter)
                .setView(content)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                    filterShowUnknown = cbFilterUnknown.isChecked();
                    filterShowAllowed = cbFilterAllowed.isChecked();
                    filterShowBlocked = cbFilterBlocked.isChecked();
                    refreshLog();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
