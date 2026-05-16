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

public class AppListActivity extends BaseActivity {
    private static final String TAG = "Aegis.Activity";
    private static final long REFRESH_INTERVAL_MS = 3000L;

    private AdapterActivity adapter = null;
    private Cursor cursor = null;
    private boolean running = false;
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_activity);
        setupBottomNav();
        running = true;

        if (getSupportActionBar() != null) {
            getSupportActionBar().hide();
        }

        ImageButton ibBack = findViewById(R.id.ibBack);
        if (ibBack != null) {
            ibBack.setOnClickListener(v -> finish());
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
        cursor = AegisDatabase.getInstance(this).getUsageByApp();
        adapter = new AdapterActivity(this, cursor);
        lvActivity.setAdapter(adapter);
        lvActivity.setOnItemClickListener((parent, view, position, id) -> {
            Cursor item = (Cursor) adapter.getItem(position);
            int uid = item.getInt(item.getColumnIndexOrThrow("uid"));
            String[] packages = getPackageManager().getPackagesForUid(uid);
            String pkg = (packages != null && packages.length > 0) ? packages[0] : "uid:" + uid;

            Intent detail = new Intent(this, AppDetailActivity.class);
            detail.putExtra(AppDetailActivity.EXTRA_UID, uid);
            detail.putExtra(AppDetailActivity.EXTRA_PACKAGE, pkg);
            startActivity(detail);
        });

        updateSummaryCard();
        updateEmptyState();
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

    private void updateSummaryCard() {
        Cursor usageCursor = null;
        long totalSent = 0L;
        long totalReceived = 0L;

        try {
            usageCursor = AegisDatabase.getInstance(this).getUsageByApp();
            int colSent = usageCursor.getColumnIndex("total_sent");
            int colReceived = usageCursor.getColumnIndex("total_received");

            while (usageCursor.moveToNext()) {
                if (colSent >= 0) {
                    totalSent += usageCursor.getLong(colSent);
                }
                if (colReceived >= 0) {
                    totalReceived += usageCursor.getLong(colReceived);
                }
            }
        } catch (Throwable ex) {
            Log.e(TAG, "Unable to update summary", ex);
        } finally {
            if (usageCursor != null) {
                usageCursor.close();
            }
        }

        TextView tvTotalSent = findViewById(R.id.tvTotalSent);
        TextView tvTotalReceived = findViewById(R.id.tvTotalReceived);
        if (tvTotalSent != null) {
            tvTotalSent.setText(AegisUtils.formatBytes(totalSent));
        }
        if (tvTotalReceived != null) {
            tvTotalReceived.setText(AegisUtils.formatBytes(totalReceived));
        }
    }

    private void updateEmptyState() {
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
        Cursor next = null;
        try {
            next = AegisDatabase.getInstance(this).getUsageByApp();
            if (adapter != null) {
                Cursor old = adapter.swapCursor(next);
                if (old != null && !old.isClosed()) {
                    old.close();
                }
                cursor = next;
            } else {
                if (next != null) {
                    next.close();
                }
            }
        } catch (Throwable ex) {
            if (next != null) {
                next.close();
            }
            Log.e(TAG, "Unable to refresh activity", ex);
        }

        updateSummaryCard();
        updateEmptyState();
    }
}
