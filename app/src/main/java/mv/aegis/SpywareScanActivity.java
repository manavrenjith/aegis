package mv.aegis;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.mv.aegis.R;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Feature 6 — spyware scanner screen. Runs {@link SpywareScanner} off the main thread and lists
 * flagged apps with their risk level and the specific reasons. For each app the user can cut its
 * network access (via the firewall — instant, always available) or launch the system uninstaller
 * (assisted removal; stock Android cannot silently delete an app). Apps holding Device Admin are
 * routed to security settings first, since they can't be uninstalled until that is revoked.
 *
 * <p>Launched from the Home dashboard's "Scan for spyware" card.
 */
public class SpywareScanActivity extends BaseActivity {

    private static final String TAG = "Aegis.SpywareUI";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final SpywareScanner scanner = new SpywareScanner();

    private LinearLayout llFindings;
    private TextView tvStatus;
    private TextView tvEmpty;
    private View pbScan;
    private Button btnScan;
    private boolean scanning;
    private volatile boolean destroyed;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_spyware_scan);

        if (getSupportActionBar() != null) {
            getSupportActionBar().hide();
        }

        ImageButton btnBack = findViewById(R.id.btnBack);
        if (btnBack != null) {
            btnBack.setOnClickListener(v -> finish());
        }

        llFindings = findViewById(R.id.llFindings);
        tvStatus = findViewById(R.id.tvStatus);
        tvEmpty = findViewById(R.id.tvEmpty);
        pbScan = findViewById(R.id.pbScan);
        btnScan = findViewById(R.id.btnScan);
        if (btnScan != null) {
            btnScan.setOnClickListener(v -> runScan());
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Re-scan on every resume so the list reflects a completed uninstall or settings change
        // when the user returns from the system uninstaller / security settings.
        runScan();
    }

    private void runScan() {
        if (scanning) {
            return;
        }
        scanning = true;
        if (pbScan != null) {
            pbScan.setVisibility(View.VISIBLE);
        }
        if (tvEmpty != null) {
            tvEmpty.setVisibility(View.GONE);
        }
        if (tvStatus != null) {
            tvStatus.setText("Scanning installed apps…");
        }
        if (btnScan != null) {
            btnScan.setEnabled(false);
        }
        if (llFindings != null) {
            llFindings.removeAllViews();
        }
        executor.execute(() -> {
            List<SpywareScanner.Finding> findings;
            try {
                findings = scanner.scan(this);
            } catch (Throwable t) {
                Log.e(TAG, "scan failed", t);
                findings = Collections.emptyList();
            }
            final List<SpywareScanner.Finding> result = findings;
            handler.post(() -> onScanDone(result));
        });
    }

    private void onScanDone(List<SpywareScanner.Finding> findings) {
        if (destroyed) {
            return;
        }
        scanning = false;
        if (pbScan != null) {
            pbScan.setVisibility(View.GONE);
        }
        if (btnScan != null) {
            btnScan.setEnabled(true);
        }
        if (findings == null || findings.isEmpty()) {
            if (tvStatus != null) {
                tvStatus.setText("Scan complete");
            }
            if (tvEmpty != null) {
                tvEmpty.setVisibility(View.VISIBLE);
            }
            return;
        }
        if (tvEmpty != null) {
            tvEmpty.setVisibility(View.GONE);
        }
        if (tvStatus != null) {
            int n = findings.size();
            tvStatus.setText(n == 1 ? "1 app needs attention" : n + " apps need attention");
        }
        renderFindings(findings);
    }

    private void renderFindings(List<SpywareScanner.Finding> findings) {
        if (llFindings == null) {
            return;
        }
        llFindings.removeAllViews();
        LayoutInflater inflater = LayoutInflater.from(this);
        for (SpywareScanner.Finding f : findings) {
            if (f == null) {
                continue;
            }
            View v = inflater.inflate(R.layout.spyware_row, llFindings, false);

            ImageView ivIcon = v.findViewById(R.id.ivIcon);
            TextView tvLabel = v.findViewById(R.id.tvLabel);
            TextView tvPackage = v.findViewById(R.id.tvPackage);
            TextView tvRisk = v.findViewById(R.id.tvRisk);
            TextView tvReasons = v.findViewById(R.id.tvReasons);
            Button btnBlock = v.findViewById(R.id.btnBlock);
            Button btnUninstall = v.findViewById(R.id.btnUninstall);

            if (ivIcon != null) {
                if (f.icon != null) {
                    ivIcon.setImageDrawable(f.icon);
                } else {
                    ivIcon.setImageResource(android.R.drawable.sym_def_app_icon);
                }
            }
            if (tvLabel != null) {
                tvLabel.setText(f.label != null ? f.label : f.packageName);
            }
            if (tvPackage != null) {
                tvPackage.setText(f.packageName);
            }
            if (tvRisk != null) {
                tvRisk.setText(riskLabel(f.risk));
                tvRisk.setBackgroundResource(riskBadgeBgRes(f.risk));
                tvRisk.setTextColor(ContextCompat.getColor(this, R.color.md_theme_onPrimary));
            }
            if (tvReasons != null) {
                tvReasons.setText(joinReasons(f.reasons));
            }
            if (btnBlock != null) {
                btnBlock.setText(f.networkBlocked ? "Unblock network" : "Block network");
                btnBlock.setOnClickListener(x -> onToggleBlock(f, btnBlock));
            }
            if (btnUninstall != null) {
                btnUninstall.setOnClickListener(x -> onUninstall(f));
            }
            llFindings.addView(v);
        }
    }

    private void onToggleBlock(final SpywareScanner.Finding f, final Button btn) {
        final boolean newState = !f.networkBlocked;
        btn.setEnabled(false);
        executor.execute(() -> {
            boolean enabled = false;
            boolean applied = false;
            try {
                android.content.SharedPreferences prefs =
                        PreferenceManager.getDefaultSharedPreferences(this);
                enabled = prefs.getBoolean("enabled", false);
                boolean manageSystem = prefs.getBoolean("manage_system", false);
                // The firewall forces system apps to "unblocked" unless manage_system is on, so a
                // block write on such an app would silently do nothing. Only claim success if it
                // will actually take effect. Unblocking is always safe.
                boolean blockCanApply = !newState || !(f.system && !manageSystem);
                if (blockCanApply) {
                    SpywareScanner.setNetworkBlocked(this, f.uid, newState);
                    applied = true;
                    if (enabled) {
                        FirewallService.reload("spyware", this, false);
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "toggle block failed for " + f.packageName, t);
            }
            final boolean fApplied = applied;
            final boolean fEnabled = enabled;
            handler.post(() -> {
                if (destroyed) {
                    return;
                }
                btn.setEnabled(true);
                String label = f.label != null ? f.label : f.packageName;
                if (!fApplied) {
                    // System app the firewall can't block without manage_system; uninstall is also
                    // unavailable for system apps — the honest option is to disable it in Settings.
                    Toast.makeText(this,
                            "Android won't let the firewall block a system app. You can disable "
                                    + label + " from Settings instead.",
                            Toast.LENGTH_LONG).show();
                    return;
                }
                f.networkBlocked = newState;
                btn.setText(newState ? "Unblock network" : "Block network");
                String msg;
                if (newState) {
                    msg = fEnabled
                            ? "Network access blocked for " + label
                            : "Blocked — takes effect when the firewall is on";
                } else {
                    msg = "Network access restored for " + label;
                }
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
            });
        });
    }

    private void onUninstall(final SpywareScanner.Finding f) {
        if (f.deviceAdmin) {
            new AlertDialog.Builder(this)
                    .setTitle("Device administrator")
                    .setMessage(f.label + " is registered as a device administrator, so Android won't "
                            + "let it be uninstalled yet. Open security settings to turn that off, "
                            + "then come back and uninstall.")
                    .setPositiveButton("Open settings", (d, w) -> {
                        if (!startSafely(new Intent(Settings.ACTION_SECURITY_SETTINGS))) {
                            startSafely(new Intent(Settings.ACTION_SETTINGS));
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        Intent uninstall = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + f.packageName));
        if (!startSafely(uninstall)) {
            Toast.makeText(this, "Couldn't open the uninstaller", Toast.LENGTH_SHORT).show();
        }
    }

    private boolean startSafely(Intent intent) {
        try {
            startActivity(intent);
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "startActivity failed for " + intent, t);
            return false;
        }
    }

    private static String joinReasons(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) {
            return "Uses sensitive permissions";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < reasons.size(); i++) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append("• ").append(reasons.get(i));
        }
        return sb.toString();
    }

    private static String riskLabel(String risk) {
        if (SpywareScanner.RISK_KNOWN.equals(risk)) {
            return "KNOWN SPYWARE";
        }
        if (SpywareScanner.RISK_HIGH.equals(risk)) {
            return "HIGH RISK";
        }
        if (SpywareScanner.RISK_MEDIUM.equals(risk)) {
            return "MEDIUM RISK";
        }
        return "LOW RISK";
    }

    private static int riskColorRes(String risk) {
        if (SpywareScanner.RISK_KNOWN.equals(risk) || SpywareScanner.RISK_HIGH.equals(risk)) {
            return R.color.color_off;
        }
        if (SpywareScanner.RISK_MEDIUM.equals(risk)) {
            return R.color.ios_warning_orange;
        }
        return R.color.color_label_secondary;
    }

    private static int riskBadgeBgRes(String risk) {
        if (SpywareScanner.RISK_KNOWN.equals(risk) || SpywareScanner.RISK_HIGH.equals(risk)) {
            return R.drawable.bg_badge_red;
        }
        if (SpywareScanner.RISK_MEDIUM.equals(risk)) {
            return R.drawable.bg_badge_orange;
        }
        return R.drawable.bg_badge_gray;
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        handler.removeCallbacksAndMessages(null);
        executor.shutdown();
        super.onDestroy();
    }
}
