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
import android.widget.ImageButton;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.mv.aegis.R;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

public class AppListActivity extends BaseActivity {
    private static final String TAG = "Aegis.Activity";
    private static final long REFRESH_INTERVAL_MS = 3000L;

    private AdapterActivity adapter = null;
    private Cursor cursor = null;
    private boolean running = false;
    private boolean refreshing = false;
    private boolean refreshPending = false;
    private boolean firstLoadDone = false;
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            if (running) {
                refresh();
                refreshHandler.postDelayed(this, REFRESH_INTERVAL_MS);
            }
        }
    };

    private final BroadcastReceiver rulesChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (running) {
                refresh();
            }
        }
    };

    private void runBg(Runnable r) {
        if (!running) {
            return;
        }
        try {
            executor.execute(r);
        } catch (RejectedExecutionException ignored) {
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_activity);
        setupBottomNav();
        com.google.android.material.bottomnavigation.BottomNavigationView bottomNav = findViewById(R.id.bottomNav);
        if (bottomNav != null) {
            bottomNav.setSelectedItemId(R.id.nav_activity);
        }
        running = true;

        if (getSupportActionBar() != null) {
            getSupportActionBar().hide();
        }

        ImageButton ibResetUsage = findViewById(R.id.ibResetUsage);
        if (ibResetUsage != null) {
            ibResetUsage.setOnClickListener(v -> new MaterialAlertDialogBuilder(this)
                    .setTitle("Reset usage")
                    .setMessage("Reset all data usage statistics?")
                    .setPositiveButton("Reset", (dialog, which) -> resetUsage())
                    .setNegativeButton("Cancel", null)
                    .show());
        }

        ListView lvActivity = findViewById(R.id.lvActivity);
        adapter = new AdapterActivity(this, null);
        lvActivity.setAdapter(adapter);
        lvActivity.setOnItemClickListener((parent, view, position, id) -> {
            Cursor item = (Cursor) adapter.getItem(position);
            int uid = item.getInt(item.getColumnIndexOrThrow("uid"));
            String[] packages = AegisUtils.packagesForUid(getPackageManager(), uid);
            String pkg = (packages != null && packages.length > 0) ? packages[0] : (uid < 0 ? "Unknown" : "uid:" + uid);

            Intent detail = new Intent(this, AppDetailActivity.class);
            detail.putExtra(AppDetailActivity.EXTRA_UID, uid);
            detail.putExtra(AppDetailActivity.EXTRA_PACKAGE, pkg);
            startActivity(detail);
        });

        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        LocalBroadcastManager.getInstance(this).registerReceiver(
                rulesChangedReceiver,
                new IntentFilter(HomeActivity.ACTION_RULES_CHANGED)
        );
        refreshHandler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS);
    }

    @Override
    protected void onPause() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(rulesChangedReceiver);
        refreshHandler.removeCallbacks(refreshRunnable);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        running = false;
        refreshHandler.removeCallbacks(refreshRunnable);
        executor.shutdown();
        if (cursor != null) {
            cursor.close();
            cursor = null;
        }
        if (adapter != null) {
            adapter.changeCursor(null);
        }
        adapter = null;
        super.onDestroy();
    }

    private void updateSummaryCard(long[] totals) {
        TextView tvTotalSent = findViewById(R.id.tvTotalSent);
        TextView tvTotalReceived = findViewById(R.id.tvTotalReceived);
        long totalSent = (totals != null && totals.length > 0) ? totals[0] : 0L;
        long totalReceived = (totals != null && totals.length > 1) ? totals[1] : 0L;
        if (tvTotalSent != null) {
            tvTotalSent.setText(AegisUtils.formatBytes(totalSent));
        }
        if (tvTotalReceived != null) {
            tvTotalReceived.setText(AegisUtils.formatBytes(totalReceived));
        }
    }

    private void updateEmptyState() {
        if (!firstLoadDone) {
            return;
        }
        TextView tvNoUsage = findViewById(R.id.tvNoUsage);
        if (tvNoUsage == null) {
            return;
        }

        boolean empty = (adapter == null || adapter.getCount() == 0);
        tvNoUsage.setVisibility(empty ? TextView.VISIBLE : TextView.GONE);
    }

    private void resetUsage() {
        new Thread(() -> {
            try {
                AegisDatabase.getInstance(this).resetUsage(-1);
                runOnUiThread(() -> {
                    Toast.makeText(this, "Usage reset", Toast.LENGTH_SHORT).show();
                    refresh();
                });
            } catch (Throwable ex) {
                Log.e(TAG, "Unable to reset usage", ex);
            }
        }).start();
    }

    private void refresh() {
        if (!running) {
            return;
        }
        if (refreshing) {
            refreshPending = true;
            return;
        }
        refreshing = true;
        runBg(() -> {
            Cursor next = null;
            try {
                next = AegisDatabase.getInstance(this).getUsageByApp();
                if (next != null) {
                    next.getCount();
                }
                long[] totals = AegisDatabase.getInstance(this).getUsageTotals();
                Cursor finalNext = next;
                refreshHandler.post(() -> {
                    refreshing = false;
                    if (!running || adapter == null) {
                        if (finalNext != null) {
                            finalNext.close();
                        }
                        return;
                    }
                    Cursor old = adapter.swapCursor(finalNext);
                    if (old != null && !old.isClosed()) {
                        old.close();
                    }
                    cursor = finalNext;
                    updateSummaryCard(totals);
                    firstLoadDone = true;
                    updateEmptyState();
                    if (refreshPending) {
                        refreshPending = false;
                        refresh();
                    }
                });
            } catch (Throwable ex) {
                Log.e(TAG, "Unable to refresh activity", ex);
                if (next != null) {
                    next.close();
                }
                refreshHandler.post(() -> {
                    refreshing = false;
                });
            }
        });
    }
}
