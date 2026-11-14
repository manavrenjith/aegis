package mv.aegis;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.util.LruCache;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import com.mv.aegis.R;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

public class AdapterActivity extends CursorAdapter {
    private static class AppInfoCache {
        final String name;
        final String pkg;

        AppInfoCache(String name, String pkg) {
            this.name = name;
            this.pkg = pkg;
        }
    }

    private PackageManager pm;
    private ExecutorService executor = Executors.newSingleThreadExecutor();
    private int colUid = -1;
    private int colSent = -1;
    private int colReceived = -1;
    private final LruCache<Integer, AppInfoCache> appInfoCache = new LruCache<>(200);
    private final LruCache<String, Drawable.ConstantState> iconCache = new LruCache<>(64);

    public AdapterActivity(Context context, Cursor cursor) {
        super(context, cursor, 0);
        pm = context.getPackageManager();
        updateColumnIndexes(cursor);
    }

    private void updateColumnIndexes(Cursor cursor) {
        if (cursor != null) {
            colUid = cursor.getColumnIndex("uid");
            colSent = cursor.getColumnIndex("total_sent");
            colReceived = cursor.getColumnIndex("total_received");
        } else {
            colUid = -1;
            colSent = -1;
            colReceived = -1;
        }
    }

    @Override
    public Cursor swapCursor(Cursor newCursor) {
        updateColumnIndexes(newCursor);
        return super.swapCursor(newCursor);
    }

    public void close() {
        executor.shutdown();
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.activity_item, parent, false);
    }

    @Override
    public void bindView(View view, Context context, Cursor cursor) {
        int uid = colUid >= 0 ? cursor.getInt(colUid) : -1;
        long sent = colSent >= 0 ? cursor.getLong(colSent) : 0L;
        long received = colReceived >= 0 ? cursor.getLong(colReceived) : 0L;

        ImageView ivIcon = view.findViewById(R.id.ivIcon);
        TextView tvName = view.findViewById(R.id.tvName);
        TextView tvPackage = view.findViewById(R.id.tvPackage);
        TextView tvSent = view.findViewById(R.id.tvSent);
        TextView tvReceived = view.findViewById(R.id.tvReceived);

        ivIcon.setImageDrawable(null);

        AppInfoCache cachedInfo = appInfoCache.get(uid);
        String name;
        String pkg;
        if (cachedInfo != null) {
            name = cachedInfo.name;
            pkg = cachedInfo.pkg;
        } else {
            try {
                List<String> names = AegisUtils.getApplicationNames(uid, context);
                if (uid < 0) {
                    name = "Unknown app";
                } else if (names.isEmpty()) {
                    if (AegisUtils.isCloneUid(uid)) {
                        int appId = uid % 100000;
                        name = "UID:" + appId + AegisUtils.cloneSuffix(uid, context);
                    } else {
                        name = Integer.toString(uid);
                    }
                } else {
                    name = names.get(0);
                }

                String[] pkgs = AegisUtils.packagesForUid(pm, uid);
                pkg = (pkgs != null && pkgs.length > 0) ? pkgs[0] : null;
                appInfoCache.put(uid, new AppInfoCache(name, pkg));
            } catch (Throwable t) {
                Log.w("AdapterActivity", "Failed to resolve name or icon for uid=" + uid, t);
                name = "UID:" + uid;
                pkg = (uid < 0 ? "Unknown" : "uid:" + uid);
            }
        }

        tvName.setText(name);
        tvPackage.setText(pkg != null ? pkg : (uid < 0 ? "Unknown" : "uid:" + uid));

        if (pkg != null) {
            final String iconPackage = pkg;
            ivIcon.setTag(iconPackage);
            Drawable.ConstantState state = iconCache.get(iconPackage);
            if (state != null) {
                ivIcon.setImageDrawable(state.newDrawable(context.getResources()));
            } else {
                try {
                    executor.execute(() -> {
                        try {
                            ApplicationInfo ai = pm.getApplicationInfo(iconPackage, 0);
                            final Drawable icon = ai.loadIcon(pm);
                            view.post(() -> {
                                Object tag = ivIcon.getTag();
                                if (tag instanceof String && iconPackage.equals(tag)) {
                                    if (icon != null && icon.getConstantState() != null) {
                                        iconCache.put(iconPackage, icon.getConstantState());
                                    }
                                    ivIcon.setImageDrawable(icon);
                                }
                            });
                        } catch (Throwable ignored) {
                            // Ignore missing or inaccessible package icon.
                        }
                    });
                } catch (RejectedExecutionException ignored) {
                }
            }
        } else {
            ivIcon.setTag(null);
            ivIcon.setImageDrawable(ContextCompat.getDrawable(context, R.drawable.ic_security_white_24dp));
        }

        tvSent.setText("\u2191 " + AegisUtils.formatBytes(sent));
        tvReceived.setText("\u2193 " + AegisUtils.formatBytes(received));
    }
}

