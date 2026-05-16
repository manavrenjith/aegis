package mv.aegis;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.mv.aegis.R;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AdapterRule extends RecyclerView.Adapter<AdapterRule.ViewHolder> implements android.widget.Filterable {

    private static final String TAG = "Aegis.Rule";

    private final Context context;
    private List<FirewallRule> listAll = new ArrayList<>();
    private List<FirewallRule> listFiltered = new ArrayList<>();
    private String currentFilter = null;
    private String currentFilterType = null;
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public AdapterRule(Context context) {
        this.context = context;
        setHasStableIds(false);
    }

    public void set(List<FirewallRule> rules) {
        listAll = new ArrayList<>(rules);
        listFiltered = new ArrayList<>(rules);
        notifyDataSetChanged();
    }

    public void filter(String type) {
        currentFilterType = type;
        getFilter().filter(currentFilter);
    }

    @Override
    public int getItemCount() {
        return listFiltered.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        final ImageView ivIcon;
        final TextView tvName;
        final TextView tvPackageName;
        final ImageButton ibWifi;
        final ImageButton ibOther;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            ivIcon = itemView.findViewById(R.id.ivIcon);
            tvName = itemView.findViewById(R.id.tvName);
            tvPackageName = itemView.findViewById(R.id.tvPackageName);
            ibWifi = itemView.findViewById(R.id.ibWifi);
            ibOther = itemView.findViewById(R.id.ibOther);
        }
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.rule, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        FirewallRule rule = listFiltered.get(position);

        holder.tvName.setText(rule.name);
        holder.tvPackageName.setText(rule.packageName == null ? "" : rule.packageName);

        holder.ivIcon.setTag(rule.packageName);
        holder.ivIcon.setImageDrawable(ContextCompat.getDrawable(context, R.drawable.ic_security_white_24dp));
        if (!TextUtils.isEmpty(rule.packageName)) {
            executor.execute(() -> {
                Drawable icon;
                try {
                    icon = context.getPackageManager().getApplicationIcon(rule.packageName);
                } catch (Throwable throwable) {
                    Log.e(TAG, "Failed to load app icon: " + rule.packageName, throwable);
                    icon = ContextCompat.getDrawable(context, R.drawable.ic_security_white_24dp);
                }

                Drawable finalIcon = icon;
                holder.ivIcon.post(() -> {
                    Object tag = holder.ivIcon.getTag();
                    if (tag != null && tag.equals(rule.packageName)) {
                        holder.ivIcon.setImageDrawable(finalIcon);
                    }
                });
            });
        }

        holder.ibWifi.setImageResource(rule.wifi_blocked ? R.drawable.wifi_off : R.drawable.wifi_on);
        holder.ibWifi.setOnClickListener(v -> {
            rule.wifi_blocked = !rule.wifi_blocked;
            holder.ibWifi.setImageResource(rule.wifi_blocked ? R.drawable.wifi_off : R.drawable.wifi_on);
            FirewallRule.updateRule(context, rule);
            FirewallService.reload("wifi", context, false);
        });

        holder.ibOther.setImageResource(rule.other_blocked ? R.drawable.other_off : R.drawable.other_on);
        holder.ibOther.setOnClickListener(v -> {
            rule.other_blocked = !rule.other_blocked;
            holder.ibOther.setImageResource(rule.other_blocked ? R.drawable.other_off : R.drawable.other_on);
            FirewallRule.updateRule(context, rule);
            FirewallService.reload("other", context, false);
        });

        LinearLayout llConfiguration = holder.itemView.findViewById(R.id.llConfiguration);
        if (llConfiguration != null) {
            llConfiguration.setVisibility(View.GONE);
        }

        View llApplication = holder.itemView.findViewById(R.id.llApplication);
        if (llApplication != null) {
            llApplication.setOnClickListener(v -> {
                if (llConfiguration == null) {
                    return;
                }
                llConfiguration.setVisibility(llConfiguration.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE);
            });
        }

        TextView tvHosts = holder.itemView.findViewById(R.id.tvHosts);
        RelativeLayout rlLockdown = holder.itemView.findViewById(R.id.rlLockdown);
        TextView tvRemarkMessaging = holder.itemView.findViewById(R.id.tvRemarkMessaging);
        TextView tvRemarkDownload = holder.itemView.findViewById(R.id.tvRemarkDownload);

        if (tvHosts != null) {
            tvHosts.setVisibility(View.GONE);
        }
        if (rlLockdown != null) {
            rlLockdown.setVisibility(View.GONE);
        }
        if (tvRemarkMessaging != null) {
            tvRemarkMessaging.setVisibility(View.GONE);
        }
        if (tvRemarkDownload != null) {
            tvRemarkDownload.setVisibility(View.GONE);
        }

        CheckBox cbWifi = holder.itemView.findViewById(R.id.cbWifi);
        CheckBox cbOther = holder.itemView.findViewById(R.id.cbOther);
        if (cbWifi != null) {
            cbWifi.setChecked(rule.wifi_blocked);
            cbWifi.setVisibility(View.GONE);
        }
        if (cbOther != null) {
            cbOther.setChecked(rule.other_blocked);
            cbOther.setVisibility(View.GONE);
        }

        wireExpandedSection(holder.itemView, rule);
    }

    private void wireExpandedSection(View view, FirewallRule rule) {
        TextView tvUid = view.findViewById(R.id.tvUid);
        TextView tvPackage = view.findViewById(R.id.tvPackage);
        TextView tvVersion = view.findViewById(R.id.tvVersion);
        TextView tvInternet = view.findViewById(R.id.tvInternet);
        TextView tvDisabled = view.findViewById(R.id.tvDisabled);
        CheckBox cbApply = view.findViewById(R.id.cbApply);
        ImageButton ibSettings = view.findViewById(R.id.ibSettings);
        ImageButton ibLaunch = view.findViewById(R.id.ibLaunch);
        LinearLayout llFilter = view.findViewById(R.id.llFilter);

        if (tvUid != null) {
            tvUid.setText("UID: " + rule.uid);
        }
        if (tvPackage != null) {
            tvPackage.setText(rule.packageName);
        }
        if (tvVersion != null) {
            tvVersion.setText(rule.version == null ? "" : "v" + rule.version);
        }
        if (tvInternet != null) {
            tvInternet.setVisibility(rule.internet ? View.GONE : View.VISIBLE);
        }
        if (tvDisabled != null) {
            tvDisabled.setVisibility(rule.enabled ? View.GONE : View.VISIBLE);
        }
        if (cbApply != null) {
            cbApply.setOnCheckedChangeListener(null);
            cbApply.setChecked(rule.apply);
            cbApply.setOnCheckedChangeListener((buttonView, isChecked) -> {
                rule.apply = isChecked;
                FirewallRule.updateRule(context, rule);
                FirewallService.reload("apply", context, false);
            });
        }

        if (ibSettings != null) {
            ibSettings.setOnClickListener(v -> {
                try {
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    intent.setData(Uri.fromParts("package", rule.packageName, null));
                    context.startActivity(intent);
                } catch (Throwable throwable) {
                    Log.e(TAG, "Failed to open app settings", throwable);
                }
            });
        }

        if (ibLaunch != null) {
            Intent launchIntent = null;
            if (!TextUtils.isEmpty(rule.packageName)) {
                launchIntent = context.getPackageManager().getLaunchIntentForPackage(rule.packageName);
            }
            if (launchIntent != null) {
                Intent finalLaunchIntent = launchIntent;
                ibLaunch.setEnabled(true);
                ibLaunch.setAlpha(1f);
                ibLaunch.setOnClickListener(v -> {
                    try {
                        context.startActivity(finalLaunchIntent);
                    } catch (Throwable throwable) {
                        Log.e(TAG, "Failed to launch app", throwable);
                    }
                });
            } else {
                ibLaunch.setEnabled(false);
                ibLaunch.setAlpha(0.4f);
                ibLaunch.setOnClickListener(null);
            }
        }

        if (llFilter != null) {
            llFilter.setVisibility(View.GONE);
        }
    }

    @Override
    public android.widget.Filter getFilter() {
        return new android.widget.Filter() {
            @Override
            protected FilterResults performFiltering(CharSequence constraint) {
                currentFilter = (constraint == null) ? null : constraint.toString();
                String needle = currentFilter == null ? "" : currentFilter.trim().toLowerCase(Locale.ROOT);
                String filterType = currentFilterType == null ? "" : currentFilterType.trim().toLowerCase(Locale.ROOT);

                List<FirewallRule> out = new ArrayList<>();
                for (FirewallRule rule : listAll) {
                    boolean textMatch;
                    if (TextUtils.isEmpty(needle)) {
                        textMatch = true;
                    } else {
                        String name = rule.name == null ? "" : rule.name.toLowerCase(Locale.ROOT);
                        String pkg = rule.packageName == null ? "" : rule.packageName.toLowerCase(Locale.ROOT);
                        textMatch = name.contains(needle) || pkg.contains(needle);
                    }

                    boolean typeMatch;
                    switch (filterType) {
                        case "blocked":
                            typeMatch = rule.wifi_blocked || rule.other_blocked;
                            break;
                        case "wifi":
                            typeMatch = !rule.wifi_blocked;
                            break;
                        case "data":
                            typeMatch = !rule.other_blocked;
                            break;
                        case "allowed":
                            typeMatch = !rule.wifi_blocked && !rule.other_blocked;
                            break;
                        default:
                            typeMatch = true;
                            break;
                    }

                    if (textMatch && typeMatch) {
                        out.add(rule);
                    }
                }

                FilterResults results = new FilterResults();
                results.values = out;
                results.count = out.size();
                return results;
            }

            @Override
            @SuppressWarnings("unchecked")
            protected void publishResults(CharSequence constraint, FilterResults results) {
                if (results != null && results.values instanceof List) {
                    listFiltered = (List<FirewallRule>) results.values;
                } else {
                    listFiltered = new ArrayList<>();
                }
                notifyDataSetChanged();
            }
        };
    }
}

