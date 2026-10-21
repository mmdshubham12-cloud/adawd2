package com.kiarash.secnode;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.text.format.Formatter;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private EditText edtSsid, edtPass;
    private TextView txtStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            requestPermissions(new String[]{
                Manifest.permission.CAMERA,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,
                Manifest.permission.CALL_PHONE,
                Manifest.permission.ACCESS_FINE_LOCATION
            }, 100);
        }

        edtSsid = findViewById(R.id.edtWifiSsid);
        edtPass = findViewById(R.id.edtWifiPass);
        txtStatus = findViewById(R.id.txtStatus);
        Button btnSaveStart = findViewById(R.id.btnSaveStart);

        final SharedPreferences prefs = getSharedPreferences("SecNodePrefs", MODE_PRIVATE);
        edtSsid.setText(prefs.getString("wifi_ssid", ""));
        edtPass.setText(prefs.getString("wifi_pass", ""));

        startService(new Intent(this, CameraBridgeService.class));
        updateIpDisplay();

        btnSaveStart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                prefs.edit()
                    .putString("wifi_ssid", edtSsid.getText().toString().trim())
                    .putString("wifi_pass", edtPass.getText().toString().trim())
                    .apply();
                startService(new Intent(MainActivity.this, CameraBridgeService.class));
                updateIpDisplay();
            }
        });
    }

    @SuppressWarnings("deprecation")
    private void updateIpDisplay() {
        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            WifiInfo info = wm != null ? wm.getConnectionInfo() : null;
            String ip = info != null ? Formatter.formatIpAddress(info.getIpAddress()) : "0.0.0.0";
            txtStatus.setText("وضعیت: فعال روی پورت اختصاصی 47821\nآی‌پی فعلی گوشی در شبکه: " + ip + ":47821\n(ویندوز به صورت خودکار این آی‌پی را در شبکه پیدا می‌کند)");
        } catch (Exception ignored) {}
    }
}
