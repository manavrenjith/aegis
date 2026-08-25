package mv.aegis;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.mv.aegis.R;

public class BaseActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        AegisUtils.setTheme(this);
        super.onCreate(savedInstanceState);
    }

    @Override
    public void setContentView(int layoutResID) {
        super.setContentView(layoutResID);
        setupWindowInsets();
    }

    @Override
    public void setContentView(View view) {
        super.setContentView(view);
        setupWindowInsets();
    }

    protected void setupWindowInsets() {
        View content = findViewById(android.R.id.content);
        if (content != null) {
            ViewCompat.setOnApplyWindowInsetsListener(content, (v, insets) -> {
                Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.statusBars());
                v.setPadding(
                        v.getPaddingLeft(),
                        systemBars.top,
                        v.getPaddingRight(),
                        v.getPaddingBottom()
                );
                return insets;
            });
            ViewCompat.requestApplyInsets(content);
        }
    }

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
