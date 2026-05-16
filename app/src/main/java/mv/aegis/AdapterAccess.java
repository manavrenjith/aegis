package mv.aegis;

import android.content.Context;
import android.database.Cursor;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.mv.aegis.R;

import java.text.SimpleDateFormat;

public class AdapterAccess extends CursorAdapter {
    private static final String TAG = "Aegis.Access";

    private int colId;
    private int colVersion;
    private int colProtocol;
    private int colDAddr;
    private int colDPort;
    private int colTime;
    private int colAllowed;
    private int colBlock;
    private int colSent;
    private int colReceived;
    private int colConnections;
    private int colorOn;
    private int colorOff;
    private int iconSize;

    public AdapterAccess(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colId = cursor.getColumnIndex("ID");
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colDAddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colAllowed = cursor.getColumnIndex("allowed");
        colBlock = cursor.getColumnIndex("block");
        colSent = cursor.getColumnIndex("sent");
        colReceived = cursor.getColumnIndex("received");
        colConnections = cursor.getColumnIndex("connections");

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;

        iconSize = AegisUtils.dips2pixels(24, context);
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.access, parent, false);
    }

    @Override
    public void bindView(View view, final Context context, Cursor cursor) {
        long id = cursor.getLong(colId);
        int version = cursor.getInt(colVersion);
        int protocol = cursor.getInt(colProtocol);
        String daddr = cursor.getString(colDAddr);
        int dport = (cursor.isNull(colDPort) ? -1 : cursor.getInt(colDPort));
        long time = cursor.getLong(colTime);
        int allowed = (cursor.isNull(colAllowed) ? -1 : cursor.getInt(colAllowed));
        int block = cursor.getInt(colBlock);
        long sent = cursor.isNull(colSent) ? 0 : cursor.getLong(colSent);
        long received = cursor.isNull(colReceived) ? 0 : cursor.getLong(colReceived);
        int connections = cursor.isNull(colConnections) ? 0 : cursor.getInt(colConnections);
        int colCount = cursor.getColumnIndex("count");
        int count = (colCount >= 0 && !cursor.isNull(colCount)) ? cursor.getInt(colCount) : 0;

        TextView tvDAddr = view.findViewById(R.id.tvDest);
        TextView tvDPort = null; // merged into tvDest
        TextView tvTime = view.findViewById(R.id.tvTime);
        ImageView ivAllowed = null; // not in layout — use ivBlock instead
        ImageView ivBlock = view.findViewById(R.id.ivBlock);
        TextView tvSent = view.findViewById(R.id.tvTraffic);
        TextView tvReceived = null; // combined in tvTraffic
        TextView tvCount = view.findViewById(R.id.tvConnections);

        if (tvDAddr != null) {
            String dest = daddr + (dport > 0 ? "/" + dport : "");
            tvDAddr.setText(dest);
        }
        tvTime.setText(SimpleDateFormat.getDateTimeInstance().format(time));

        if (ivBlock != null) {
            if (block < 0)
                ivBlock.setVisibility(View.GONE);
            else {
                ivBlock.setVisibility(View.VISIBLE);
                ivBlock.setImageResource(block == 0 ? R.drawable.host_allowed : R.drawable.host_blocked);
            }
        }

        if (tvSent != null) {
            String traffic = "";
            if (sent > 0 || received > 0)
                traffic = "↑" + AegisUtils.formatBytes(sent) + " ↓" + AegisUtils.formatBytes(received);
            tvSent.setText(traffic);
            view.findViewById(R.id.llTraffic).setVisibility(traffic.isEmpty() ? View.GONE : View.VISIBLE);
        }
        if (tvCount != null)
            tvCount.setText(connections > 0 ? "×" + connections : "");
    }
}

