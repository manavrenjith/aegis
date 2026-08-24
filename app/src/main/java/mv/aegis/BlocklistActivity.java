package mv.aegis;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.mv.aegis.R;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * In-app blocklist manager (Feature 5). Lets the user view every domain in the malicious-domain
 * blocklist, add their own, and remove any entry — bundled samples included. Edits are written to
 * the SQLite {@code blocklist} table; if the firewall is currently on, the running
 * {@link FirewallService} is told to refresh its in-memory set so changes take effect immediately.
 *
 * <p>Launched from the Home screen's overflow (⋮) menu.
 */
public class BlocklistActivity extends BaseActivity {

    private static final String TAG = "Aegis.Blocklist";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    private LinearLayout llContainer;
    private TextView tvEmpty;
    private EditText etDomain;
    private volatile boolean destroyed;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_blocklist);

        if (getSupportActionBar() != null) {
            getSupportActionBar().hide();
        }

        ImageButton btnBack = findViewById(R.id.btnBack);
        if (btnBack != null) {
            btnBack.setOnClickListener(v -> finish());
        }

        llContainer = findViewById(R.id.llContainer);
        tvEmpty = findViewById(R.id.tvEmpty);
        etDomain = findViewById(R.id.etDomain);

        Button btnAdd = findViewById(R.id.btnAdd);
        if (btnAdd != null) {
            btnAdd.setOnClickListener(v -> onAddClicked());
        }
        if (etDomain != null) {
            etDomain.setOnEditorActionListener((v, actionId, event) -> {
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    onAddClicked();
                    return true;
                }
                return false;
            });
        }

        refresh();
    }

    private void onAddClicked() {
        String raw = etDomain == null ? null : etDomain.getText().toString();
        final String domain = sanitizeDomain(raw);
        if (domain == null) {
            Toast.makeText(this, "Enter a valid domain, e.g. example.com", Toast.LENGTH_SHORT).show();
            return;
        }
        if (etDomain != null) {
            etDomain.setText("");
        }
        executor.execute(() -> {
            boolean added = false;
            try {
                added = AegisDatabase.getInstance(this).addBlocklistDomain(domain, "user");
            } catch (Throwable t) {
                Log.e(TAG, "add failed for " + domain, t);
            }
            final boolean fAdded = added;
            pushReloadIfRunning();
            final List<String[]> rows = loadRows();
            handler.post(() -> {
                if (destroyed) {
                    return;
                }
                Toast.makeText(this,
                        fAdded ? domain + " added to blocklist"
                                : domain + " is already in the blocklist",
                        Toast.LENGTH_SHORT).show();
                renderRows(rows);
            });
        });
    }

    private void onDeleteClicked(final String domain) {
        executor.execute(() -> {
            try {
                AegisDatabase.getInstance(this).deleteBlocklistDomain(domain);
            } catch (Throwable t) {
                Log.e(TAG, "delete failed for " + domain, t);
            }
            pushReloadIfRunning();
            final List<String[]> rows = loadRows();
            handler.post(() -> {
                if (destroyed) {
                    return;
                }
                Toast.makeText(this, domain + " removed", Toast.LENGTH_SHORT).show();
                renderRows(rows);
            });
        });
    }

    /**
     * If the firewall is on, ask the running service to refresh its in-memory blocklist. When the
     * firewall is off the service is stopped, so there is nothing to refresh — it reloads the whole
     * table from the database on its next start (see {@link FirewallService} onCreate).
     */
    private void pushReloadIfRunning() {
        try {
            boolean enabled = PreferenceManager.getDefaultSharedPreferences(this)
                    .getBoolean("enabled", false);
            if (enabled) {
                FirewallService.reloadBlocklist("blocklist edited", this);
            }
        } catch (Throwable t) {
            Log.e(TAG, "reload push failed", t);
        }
    }

    private void refresh() {
        executor.execute(() -> {
            final List<String[]> rows = loadRows();
            handler.post(() -> {
                if (destroyed) {
                    return;
                }
                renderRows(rows);
            });
        });
    }

    private List<String[]> loadRows() {
        try {
            return AegisDatabase.getInstance(this).listBlocklist();
        } catch (Throwable t) {
            Log.e(TAG, "list failed", t);
            return Collections.emptyList();
        }
    }

    private void renderRows(List<String[]> rows) {
        if (llContainer == null) {
            return;
        }
        llContainer.removeAllViews();
        if (rows == null || rows.isEmpty()) {
            if (tvEmpty != null) {
                tvEmpty.setVisibility(View.VISIBLE);
            }
            return;
        }
        if (tvEmpty != null) {
            tvEmpty.setVisibility(View.GONE);
        }

        LayoutInflater inflater = LayoutInflater.from(this);
        for (String[] row : rows) {
            if (row == null || row.length == 0 || row[0] == null) {
                continue;
            }
            final String domain = row[0];
            String source = row.length > 1 ? row[1] : null;

            View v = inflater.inflate(R.layout.blocklist_row, llContainer, false);
            TextView tvDomain = v.findViewById(R.id.tvDomain);
            TextView tvSource = v.findViewById(R.id.tvSource);
            ImageButton btnDelete = v.findViewById(R.id.btnDelete);

            if (tvDomain != null) {
                tvDomain.setText(domain);
            }
            if (tvSource != null) {
                tvSource.setText("user".equals(source) ? "Added by you" : "Bundled sample");
            }
            if (btnDelete != null) {
                btnDelete.setContentDescription("Remove " + domain);
                btnDelete.setOnClickListener(x -> onDeleteClicked(domain));
            }
            llContainer.addView(v);
        }
    }

    /**
     * Normalizes user input to a bare hostname: strips scheme, any userinfo, path, and port,
     * removes a trailing dot, lowercases, and validates it looks like a domain. Returns null if the
     * input is not a plausible domain. Note: www is NOT stripped, because blocklist matching is
     * exact (www.example.com and example.com are treated as different hosts).
     */
    static String sanitizeDomain(String raw) {
        if (raw == null) {
            return null;
        }
        String d = raw.trim().toLowerCase(Locale.ROOT);
        if (d.isEmpty()) {
            return null;
        }
        int scheme = d.indexOf("://");
        if (scheme >= 0) {
            d = d.substring(scheme + 3);
        }
        // Strip the path BEFORE userinfo/port so an '@' or ':' living inside a path can't be
        // mistaken for an authority delimiter (e.g. "good.com/x@evil.com" must yield good.com).
        int slash = d.indexOf('/');
        if (slash >= 0) {
            d = d.substring(0, slash);
        }
        int at = d.indexOf('@');
        if (at >= 0) {
            d = d.substring(at + 1);
        }
        int colon = d.indexOf(':');
        if (colon >= 0) {
            d = d.substring(0, colon);
        }
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        // Valid hostname: dot-separated labels of [a-z0-9-] (no leading/trailing hyphen), a
        // letters-only TLD of >=2, overall 4..253 chars.
        if (!d.matches("^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$")) {
            return null;
        }
        return d;
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        handler.removeCallbacksAndMessages(null);
        executor.shutdown();
        super.onDestroy();
    }
}
