package mv.aegis;

import android.content.Intent;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.mv.aegis.R;

public class BaseActivity extends AppCompatActivity {
    protected void setupBottomNav() {
        BottomNavigationView bottomNav = findViewById(R.id.bottomNav);
        if (bottomNav == null) {
            return;
        }

        bottomNav.setOnItemSelectedListener(item -> {
            Class<?> target = null;
            int itemId = item.getItemId();
            if (itemId == R.id.nav_home) {
                target = HomeActivity.class;
            } else if (itemId == R.id.nav_activity) {
                target = AppListActivity.class;
            } else if (itemId == R.id.nav_log) {
                target = LogActivity.class;
            } else if (itemId == R.id.nav_settings) {
                target = SettingsActivity.class;
            }

            if (target == null || getClass().equals(target)) {
                return true;
            }

            Intent intent = new Intent(this, target);
            intent.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
            startActivity(intent);
            overridePendingTransition(0, 0);
            return true;
        });
    }
}
