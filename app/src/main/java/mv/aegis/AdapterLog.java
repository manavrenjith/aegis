package mv.aegis;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.mv.aegis.R;

import java.text.DateFormat;
import java.util.List;

public class AdapterLog extends RecyclerView.Adapter<AdapterLog.LogViewHolder> {

    private final Context context;
    private final LayoutInflater inflater;
    private final PackageManager packageManager;
    private Cursor cursor;

    public AdapterLog(Context context) {
        this.context = context;
        this.inflater = LayoutInflater.from(context);
        this.packageManager = context.getPackageManager();
        setHasStableIds(true);
    }

    public void swapCursor(Cursor newCursor) {
        Cursor oldCursor = cursor;
        cursor = newCursor;
        notifyDataSetChanged();
        if (oldCursor != null && oldCursor != newCursor && !oldCursor.isClosed()) {
            oldCursor.close();
        }
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = inflater.inflate(R.layout.log_row, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        if (cursor == null || cursor.isClosed() || !cursor.moveToPosition(position)) {
            return;
        }

        int uid = cursor.getInt(cursor.getColumnIndexOrThrow("uid"));
        String daddr = cursor.getString(cursor.getColumnIndexOrThrow("daddr"));
        String dname = cursor.getString(cursor.getColumnIndexOrThrow("dname"));
        int dport = cursor.getInt(cursor.getColumnIndexOrThrow("dport"));
        long time = cursor.getLong(cursor.getColumnIndexOrThrow("time"));
        int allowed = cursor.getInt(cursor.getColumnIndexOrThrow("allowed"));

        List<String> names = AegisUtils.getApplicationNames(uid, context);
        String appName = names.isEmpty() ? ("UID:" + uid) : TextUtils.join(", ", names);
        holder.tvAppName.setText(appName);

        String domain = !TextUtils.isEmpty(dname) ? dname : daddr;
        if (dport > 0) {
            domain = domain + ":" + dport;
        }
        holder.tvDomain.setText(domain);

        holder.tvTimestamp.setText(DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(time));

        holder.vDot.setBackground(buildDot(allowed == 1
                ? ContextCompat.getColor(context, R.color.color_on)
                : ContextCompat.getColor(context, R.color.color_off)));

        holder.ivAppIcon.setImageDrawable(resolveIcon(uid));
    }

    @Override
    public int getItemCount() {
        return cursor == null ? 0 : cursor.getCount();
    }

    @Override
    public long getItemId(int position) {
        if (cursor == null || !cursor.moveToPosition(position)) {
            return RecyclerView.NO_ID;
        }
        int idIndex = cursor.getColumnIndex("_id");
        return idIndex >= 0 ? cursor.getLong(idIndex) : position;
    }

    private Drawable resolveIcon(int uid) {
        String[] packages = packageManager.getPackagesForUid(uid);
        if (packages != null && packages.length > 0) {
            try {
                return packageManager.getApplicationIcon(packages[0]);
            } catch (PackageManager.NameNotFoundException ignored) {
                // Fall through to default icon.
            }
        }
        return ContextCompat.getDrawable(context, R.drawable.ic_security_white_24dp);
    }

    private Drawable buildDot(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(color);
        return drawable;
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        final ImageView ivAppIcon;
        final View vDot;
        final TextView tvAppName;
        final TextView tvDomain;
        final TextView tvTimestamp;

        LogViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.ivAppIcon);
            vDot = itemView.findViewById(R.id.vDot);
            tvAppName = itemView.findViewById(R.id.tvAppName);
            tvDomain = itemView.findViewById(R.id.tvDomain);
            tvTimestamp = itemView.findViewById(R.id.tvTimestamp);
        }
    }
}

