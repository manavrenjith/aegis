package mv.aegis;

import android.content.Intent;
import android.os.Bundle;

import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;

import com.mv.aegis.R;

public class FragmentSettings extends PreferenceFragmentCompat {
    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.preferences, rootKey);
    }

    @Override
    public boolean onPreferenceTreeClick(Preference preference) {
        if ("manage_blocklist".equals(preference.getKey())) {
            startActivity(new Intent(requireContext(), BlocklistActivity.class));
            return true;
        }
        if (preference instanceof PreferenceScreen) {
            String key = preference.getKey();
            if (key != null) {
                FragmentSettings fragment = new FragmentSettings();
                Bundle args = new Bundle();
                args.putString(ARG_PREFERENCE_ROOT, key);
                fragment.setArguments(args);

                getParentFragmentManager()
                        .beginTransaction()
                        .replace(R.id.settings_container, fragment)
                        .addToBackStack(null)
                        .commit();
                return true;
            }
        }
        return super.onPreferenceTreeClick(preference);
    }
}
