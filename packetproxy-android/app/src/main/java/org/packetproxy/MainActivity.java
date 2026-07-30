package org.packetproxy;

import android.os.Bundle;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!Python.isStarted()) {
            Python.start(new AndroidPlatform(this));
        }

        // Start foreground service for persistent background operation
        Intent serviceIntent = new Intent(this, ProxyService.class);
        startForegroundService(serviceIntent);

        // Launch the Kivy app from Python
        Python.getInstance()
            .getModule("main")
            .callAttr("run_app");

        finish();
    }
}
