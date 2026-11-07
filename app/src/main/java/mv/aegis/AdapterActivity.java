package mv.aegis;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.mv.aegis.R;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AdapterActivity extends CursorAdapter {
    private PackageManager pm;
    private ExecutorService executor = Executors.newSingleThreadExecutor();

    public AdapterActivity(Context context, Cursor cursor) {
        super(context, cursor, 0);
        pm = context.getPackageManager();
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.activity_item, parent, false);
    }

    @Override
    public void bindView(View view, Context context, Cursor cursor) {
        int uid = cursor.getInt(cursor.getColumnIndexOrThrow("uid"));
        long sent = cursor.getLong(cursor.getColumnIndexOrThrow("total_sent"));
        long received = cursor.getLong(cursor.getColumnIndexOrThrow("total_received"));

        ImageView ivIcon = view.findViewById(R.id.ivIcon);
        TextView tvName = view.findViewById(R.id.tvName);
        TextView tvPackage = view.findViewById(R.id.tvPackage);
        TextView tvSent = view.findViewById(R.id.tvSent);
        TextView tvReceived = view.findViewById(R.id.tvReceived);

        ivIcon.setImageDrawable(null);

        List<String> names = AegisUtils.getApplicationNames(uid, context);
        if (uid < 0) {
            tvName.setText("Unknown app");
        } else if (names.isEmpty()) {
            if (uid >= 100000 && (uid % 100000) >= 10000) {
                int appId = uid % 100000;
                int n = uid / 100000;
                tvName.setText("UID:" + appId + " (user " + n + ")");
            } else {
                tvName.setText(Integer.toString(uid));
            }
        } else {
            tvName.setText(names.get(0));
        }

        String[] pkgs = null;
        try {
            pkgs = pm.getPackagesForUid(uid);
            if ((pkgs == null || pkgs.length == 0) && uid >= 100000 && (uid % 100000) >= 10000) {
                pkgs = pm.getPackagesForUid(uid % 100000);
            }
        } catch (SecurityException e) {
            Log.w("AdapterActivity", "Cannot get packages for uid=" + uid);
        }
        String pkg = (pkgs != null && pkgs.length > 0) ? pkgs[0] : null;
        tvPackage.setText(pkg != null ? pkg : (uid < 0 ? "Unknown" : "uid:" + uid));

        if (pkg != null) {
            final String iconPackage = pkg;
            ivIcon.setTag(iconPackage);
            executor.execute(() -> {
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(iconPackage, 0);
                    final Drawable icon = ai.loadIcon(pm);
                    view.post(() -> {
                        Object tag = ivIcon.getTag();
                        if (tag instanceof String && iconPackage.equals(tag)) {
                            ivIcon.setImageDrawable(icon);
                        }
                    });
                } catch (Throwable ignored) {
                    // Ignore missing or inaccessible package icon.
                }
            });
        }

        tvSent.setText("\u2191 " + AegisUtils.formatBytes(sent));
        tvReceived.setText("\u2193 " + AegisUtils.formatBytes(received));
    }
}

