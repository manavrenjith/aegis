package mv.aegis;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.util.Log;
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
import java.util.TimeZone;

public class AdapterLog extends RecyclerView.Adapter<AdapterLog.LogViewHolder> {

    private final Context context;
    private final LayoutInflater inflater;
    private final PackageManager packageManager;
    private final DateFormat dateTimeFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
    private final DateFormat timeFormat = DateFormat.getTimeInstance(DateFormat.SHORT);
    private static final long DAY_IN_MILLIS = 86400000L;

    private Cursor cursor;
    private int colId = -1;
    private int colUid = -1;
    private int colDaddr = -1;
    private int colDname = -1;
    private int colDport = -1;
    private int colTime = -1;
    private int colAllowed = -1;
    private int colPacketCount = -1;
    private int colScreenOffCount = -1;
    private int colTimeEnd = -1;
    private int colConnection = -1;

    public AdapterLog(Context context) {
        this.context = context;
        this.inflater = LayoutInflater.from(context);
        this.packageManager = context.getPackageManager();
        setHasStableIds(true);
    }

    public void swapCursor(Cursor newCursor) {
        Cursor oldCursor = cursor;
        cursor = newCursor;
        if (newCursor != null && !newCursor.isClosed()) {
            colId = newCursor.getColumnIndex("_id");
            colUid = newCursor.getColumnIndex("uid");
            colDaddr = newCursor.getColumnIndex("daddr");
            colDname = newCursor.getColumnIndex("dname");
            colDport = newCursor.getColumnIndex("dport");
            colTime = newCursor.getColumnIndex("time");
            colAllowed = newCursor.getColumnIndex("allowed");
            colPacketCount = newCursor.getColumnIndex("packet_count");
            colScreenOffCount = newCursor.getColumnIndex("screen_off_count");
            colTimeEnd = newCursor.getColumnIndex("time_end");
            colConnection = newCursor.getColumnIndex("connection");
        } else {
            colId = -1;
            colUid = -1;
            colDaddr = -1;
            colDname = -1;
            colDport = -1;
            colTime = -1;
            colAllowed = -1;
            colPacketCount = -1;
            colScreenOffCount = -1;
            colTimeEnd = -1;
            colConnection = -1;
        }
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

        boolean isNullUid = colUid < 0 || cursor.isNull(colUid);
        int uid = isNullUid ? -1 : cursor.getInt(colUid);
        String daddr = colDaddr >= 0 ? cursor.getString(colDaddr) : null;
        String dname = colDname >= 0 ? cursor.getString(colDname) : null;
        int dport = colDport >= 0 ? cursor.getInt(colDport) : 0;
        long time = colTime >= 0 ? cursor.getLong(colTime) : 0L;
        int allowed = colAllowed >= 0 ? cursor.getInt(colAllowed) : 0;

        try {
            String appName;
            if (isNullUid || uid < 0) {
                appName = "Unknown app";
            } else {
                List<String> names = AegisUtils.getApplicationNames(uid, context);
                if (!names.isEmpty()) {
                    appName = TextUtils.join(", ", names);
                } else if (AegisUtils.isCloneUid(uid)) {
                    appName = "UID:" + (uid % 100000) + AegisUtils.cloneSuffix(uid, context);
                } else {
                    appName = "UID:" + uid;
                }
            }
            holder.tvAppName.setText(appName);
            holder.ivAppIcon.setImageDrawable(resolveIcon(uid));
        } catch (Throwable t) {
            Log.w("AdapterLog", "Failed to resolve name or icon for uid=" + uid, t);
            holder.tvAppName.setText("UID:" + uid);
            holder.ivAppIcon.setImageDrawable(ContextCompat.getDrawable(context, R.drawable.ic_security_white_24dp));
        }

        int packetCount = (colPacketCount >= 0 && !cursor.isNull(colPacketCount)) ? cursor.getInt(colPacketCount) : 1;
        int screenOffCount = (colScreenOffCount >= 0 && !cursor.isNull(colScreenOffCount)) ? cursor.getInt(colScreenOffCount) : 0;
        Long timeEnd = (colTimeEnd >= 0 && !cursor.isNull(colTimeEnd)) ? cursor.getLong(colTimeEnd) : null;

        StringBuilder sb = new StringBuilder();
        if (timeEnd != null && timeEnd != time) {
            String startStr = dateTimeFormat.format(time);
            String endStr = dateTimeFormat.format(timeEnd);
            if (startStr.equals(endStr)) {
                sb.append(startStr);
            } else if (isSameDay(time, timeEnd)) {
                sb.append(startStr).append(" - ").append(timeFormat.format(timeEnd));
            } else {
                sb.append(startStr).append(" - ").append(endStr);
            }
        } else {
            sb.append(dateTimeFormat.format(time));
        }

        if (packetCount > 1) {
            sb.append("\n\u00d7").append(packetCount).append(" packets");
            if (screenOffCount > 0) {
                sb.append(" \u00b7 ").append(screenOffCount).append(" screen-off");
            }
        }
        holder.tvTimestamp.setText(sb.toString());
        holder.tvTimestamp.setMaxLines(packetCount > 1 ? 3 : 1);

        if (allowed == Packet.STATUS_OVERFLOW) {
            int count = colConnection >= 0 ? cursor.getInt(colConnection) : 0;
            holder.tvDomain.setText(count + " more destinations");
            holder.tvAddr.setVisibility(View.GONE);
            holder.vDot.setBackground(buildDot(ContextCompat.getColor(context, R.color.color_label_tertiary)));
        } else {
            String addr = daddr != null ? daddr : "";
            if (dport > 0 && !addr.isEmpty()) {
                addr = addr + ":" + dport;
            }

            if (!TextUtils.isEmpty(dname) && !addr.isEmpty()) {
                holder.tvDomain.setText(dname);
                holder.tvAddr.setText(addr);
                holder.tvAddr.setVisibility(View.VISIBLE);
            } else if (!TextUtils.isEmpty(dname) && addr.isEmpty()) {
                holder.tvDomain.setText(dname);
                holder.tvAddr.setVisibility(View.GONE);
            } else {
                holder.tvDomain.setText(addr);
                holder.tvAddr.setVisibility(View.GONE);
            }

            holder.vDot.setBackground(buildDot(allowed == 1
                    ? ContextCompat.getColor(context, R.color.color_on)
                    : ContextCompat.getColor(context, R.color.color_off)));
        }


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
        return colId >= 0 ? cursor.getLong(colId) : position;
    }

    private Drawable resolveIcon(int uid) {
        String[] packages = AegisUtils.packagesForUid(packageManager, uid);
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

    private static boolean isSameDay(long t1, long t2) {
        TimeZone tz = TimeZone.getDefault();
        return (t1 + tz.getOffset(t1)) / DAY_IN_MILLIS == (t2 + tz.getOffset(t2)) / DAY_IN_MILLIS;
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        final ImageView ivAppIcon;
        final View vDot;
        final TextView tvAppName;
        final TextView tvDomain;
        final TextView tvAddr;
        final TextView tvTimestamp;

        LogViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.ivAppIcon);
            vDot = itemView.findViewById(R.id.vDot);
            tvAppName = itemView.findViewById(R.id.tvAppName);
            tvDomain = itemView.findViewById(R.id.tvDomain);
            tvAddr = itemView.findViewById(R.id.tvAddr);
            tvTimestamp = itemView.findViewById(R.id.tvTimestamp);
        }
    }
}

