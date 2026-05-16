package mv.aegis;

import android.content.Intent;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import com.mv.aegis.R;

public class BaseActivity extends AppCompatActivity {
    protected void setupBottomNav() {
        View tabHome = findViewById(R.id.tabHome);
        if (tabHome != null) {
            tabHome.setOnClickListener(v -> startActivity(new Intent(this, HomeActivity.class)));
        }

        View tabLog = findViewById(R.id.tabLog);
        if (tabLog != null) {
            tabLog.setOnClickListener(v -> startActivity(new Intent(this, LogActivity.class)));
        }

        View tabActivity = findViewById(R.id.tabActivity);
        if (tabActivity != null) {
            tabActivity.setOnClickListener(v -> startActivity(new Intent(this, AppListActivity.class)));
        }

        View tabSettings = findViewById(R.id.tabSettings);
        if (tabSettings != null) {
            tabSettings.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        }
    }
}

