package mv.aegis;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
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
    private static final long DEBOUNCE_INTERVAL_MS = 1000L;

    private AdapterLog adapter;
    private RecyclerView rvLog;
    private TextView tvDisabled;
    private boolean filterShowUnknown = true;
    private boolean filterShowAllowed = true;
    private boolean filterShowBlocked = true;
    private long lastRefreshTime = 0L;
    private boolean refreshScheduled = false;
    private boolean isStopped = false;
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
            if (!isStopped) {
                scheduleRefresh();
                handler.postDelayed(this, REFRESH_INTERVAL_MS);
            }
        }
    };

    private final Runnable debouncedRefreshRunnable = new Runnable() {
        @Override
        public void run() {
            refreshScheduled = false;
            if (isStopped) {
                return;
            }
            refreshLog();
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
    protected void onStart() {
        super.onStart();
        isStopped = false;
    }

    @Override
    protected void onResume() {
        super.onResume();
        isStopped = false;
        AegisDatabase.getInstance(this).addLogChangedListener(logChangedListener);
        LocalBroadcastManager.getInstance(this)
                .registerReceiver(rulesReceiver, new IntentFilter(HomeActivity.ACTION_RULES_CHANGED));
        handler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS);
        scheduleRefresh();
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refreshRunnable);
        handler.removeCallbacks(debouncedRefreshRunnable);
        refreshScheduled = false;
        AegisDatabase.getInstance(this).removeLogChangedListener(logChangedListener);
        LocalBroadcastManager.getInstance(this).unregisterReceiver(rulesReceiver);
        super.onPause();
    }

    @Override
    protected void onStop() {
        isStopped = true;
        refreshScheduled = false;
        handler.removeCallbacks(debouncedRefreshRunnable);
        handler.removeCallbacks(refreshRunnable);
        super.onStop();
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
        if (isStopped) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        long elapsed = now - lastRefreshTime;
        if (elapsed >= DEBOUNCE_INTERVAL_MS) {
            if (!refreshScheduled) {
                refreshLog();
            }
        } else if (!refreshScheduled) {
            refreshScheduled = true;
            handler.postDelayed(debouncedRefreshRunnable, DEBOUNCE_INTERVAL_MS - elapsed);
        }
    }

    private void refreshLog() {
        if (isStopped) {
            return;
        }
        lastRefreshTime = SystemClock.elapsedRealtime();
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
                    LinearLayoutManager lm = (LinearLayoutManager) rvLog.getLayoutManager();
                    int firstPos = lm != null ? lm.findFirstVisibleItemPosition() : 0;
                    View firstView = (firstPos > 0 && lm != null) ? lm.findViewByPosition(firstPos) : null;
                    int offset = firstView != null ? firstView.getTop() : 0;

                    adapter.swapCursor(result);

                    if (lm != null) {
                        if (firstPos <= 0) {
                            if (adapter.getItemCount() > 0) {
                                rvLog.scrollToPosition(0);
                            }
                        } else {
                            lm.scrollToPositionWithOffset(firstPos, offset);
                        }
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
                    executor.execute(() -> {
                        AegisDatabase.getInstance(this).clearLog(-1);
                        handler.post(this::scheduleRefresh);
                    });
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
                    scheduleRefresh();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
