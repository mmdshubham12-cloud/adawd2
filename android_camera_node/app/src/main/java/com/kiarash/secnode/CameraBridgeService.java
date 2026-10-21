package com.kiarash.secnode;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.ImageFormat;
import android.graphics.Rect;
import android.graphics.SurfaceTexture;
import android.graphics.YuvImage;
import android.hardware.Camera;
import android.net.DhcpInfo;
import android.net.Uri;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.IBinder;
import android.os.PowerManager;
import android.telephony.SmsManager;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.json.JSONArray;
import org.json.JSONObject;

@SuppressWarnings("deprecation")
public class CameraBridgeService extends Service {
    public static final int CAMERA_PORT = 47821;
    public static final int UDP_DISCOVERY_PORT = 47822;

    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private Camera camera;
    private SurfaceTexture dummySurface;
    private volatile byte[] latestJpeg = null;
    private boolean running = true;

    @Override
    public void onCreate() {
        super.onCreate();
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (pm != null) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "KiarashSec::CpuWakeLock");
            wakeLock.acquire();
        }
        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "KiarashSec::WifiLock");
            wifiLock.acquire();
        }

        Notification notification = new Notification.Builder(this)
            .setContentTitle("سیستم امنیتی کیارش (پورت 47821)")
            .setContentText("ارسال تصویر و پل ارتباطی اضطراری ۲۴/۷")
            .setSmallIcon(android.R.drawable.ic_menu_camera)
            .build();
        startForeground(101, notification);

        initCameraBackground();
        startWifiWatchdog();
        startUdpDiscoveryBeacon();
        startHttpServer();
    }

    private void initCameraBackground() {
        try {
            camera = Camera.open(0);
            dummySurface = new SurfaceTexture(10);
            camera.setPreviewTexture(dummySurface);
            Camera.Parameters params = camera.getParameters();
            params.setPreviewFormat(ImageFormat.NV21);
            params.setPreviewSize(640, 480);
            camera.setParameters(params);
            camera.setPreviewCallback(new Camera.PreviewCallback() {
                @Override
                public void onPreviewFrame(byte[] data, Camera cam) {
                    try {
                        YuvImage yuv = new YuvImage(data, ImageFormat.NV21, 640, 480, null);
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        yuv.compressToJpeg(new Rect(0, 0, 640, 480), 75, out);
                        latestJpeg = out.toByteArray();
                    } catch (Exception ignored) {}
                }
            });
            camera.startPreview();
        } catch (Exception ignored) {}
    }

    private void startWifiWatchdog() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    try {
                        SharedPreferences prefs = getSharedPreferences("SecNodePrefs", MODE_PRIVATE);
                        String targetSsid = prefs.getString("wifi_ssid", "");
                        String targetPass = prefs.getString("wifi_pass", "");
                        if (!targetSsid.isEmpty()) {
                            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                            if (wm != null) {
                                if (!wm.isWifiEnabled()) wm.setWifiEnabled(true);
                                WifiInfo info = wm.getConnectionInfo();
                                String currentSsid = info != null ? info.getSSID() : "";
                                if (currentSsid == null || !currentSsid.contains(targetSsid)) {
                                    WifiConfiguration conf = new WifiConfiguration();
                                    conf.SSID = "\"" + targetSsid + "\"";
                                    conf.preSharedKey = "\"" + targetPass + "\"";
                                    int netId = wm.addNetwork(conf);
                                    wm.disconnect();
                                    wm.enableNetwork(netId, true);
                                    wm.reconnect();
                                }
                            }
                        }
                        Thread.sleep(10000);
                    } catch (Exception ignored) {}
                }
            }
        }).start();
    }

    private InetAddress getSubnetBroadcastAddress() {
        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                DhcpInfo dhcp = wm.getDhcpInfo();
                if (dhcp != null && dhcp.ipAddress != 0) {
                    int broadcast = (dhcp.ipAddress & dhcp.netmask) | ~dhcp.netmask;
                    byte[] quads = new byte[4];
                    for (int k = 0; k < 4; k++) {
                        quads[k] = (byte) ((broadcast >> (k * 8)) & 0xFF);
                    }
                    return InetAddress.getByAddress(quads);
                }
            }
        } catch (Exception ignored) {}
        try {
            return InetAddress.getByName("255.255.255.255");
        } catch (Exception e) {
            return null;
        }
    }

    private void startUdpDiscoveryBeacon() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    try {
                        DatagramSocket socket = new DatagramSocket();
                        socket.setBroadcast(true);
                        byte[] msg = ("KIARASH_CAMERA_NODE:" + CAMERA_PORT).getBytes("UTF-8");
                        InetAddress bcast = getSubnetBroadcastAddress();
                        if (bcast != null) {
                            socket.send(new DatagramPacket(msg, msg.length, bcast, UDP_DISCOVERY_PORT));
                        }
                        socket.send(new DatagramPacket(msg, msg.length, InetAddress.getByName("255.255.255.255"), UDP_DISCOVERY_PORT));
                        socket.close();
                        Thread.sleep(4000);
                    } catch (Exception ignored) {}
                }
            }
        }).start();
    }

    private void startHttpServer() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ServerSocket server = new ServerSocket(CAMERA_PORT);
                    while (running) {
                        final Socket client = server.accept();
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                handleClient(client);
                            }
                        }).start();
                    }
                } catch (Exception ignored) {}
            }
        }).start();
    }

    private void handleClient(Socket client) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
            OutputStream out = client.getOutputStream();
            String requestLine = reader.readLine();
            if (requestLine == null) {
                client.close();
                return;
            }

            int contentLength = 0;
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase().startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.split(":")[1].trim());
                }
            }

            if (requestLine.startsWith("GET /ping") || requestLine.startsWith("GET /status")) {
                out.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nKIARASH_CAM_OK".getBytes());
                out.flush();
                client.close();
            } else if (requestLine.startsWith("GET /video")) {
                out.write(("HTTP/1.1 200 OK\r\n" +
                    "Content-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n").getBytes());
                while (running && !client.isClosed()) {
                    if (latestJpeg != null) {
                        out.write(("--frame\r\nContent-Type: image/jpeg\r\n\r\n").getBytes());
                        out.write(latestJpeg);
                        out.write("\r\n".getBytes());
                        out.flush();
                    }
                    Thread.sleep(66);
                }
            } else if (requestLine.startsWith("POST /trigger_emergency")) {
                char[] bodyChars = new char[contentLength];
                reader.read(bodyChars, 0, contentLength);
                JSONObject json = new JSONObject(new String(bodyChars));
                final JSONArray numbers = json.optJSONArray("numbers");
                final boolean callEnabled = json.optBoolean("call_enabled", true);
                final boolean smsEnabled = json.optBoolean("sms_enabled", true);
                final String message = json.optString("message", "Security Alert!");

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        executeSequentialEmergency(numbers, callEnabled, smsEnabled, message);
                    }
                }).start();

                out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}".getBytes());
                out.flush();
                client.close();
            } else {
                out.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nKIARASH_CAM_OK".getBytes());
                out.flush();
                client.close();
            }
        } catch (Exception ignored) {}
    }

    private void executeSequentialEmergency(JSONArray numbers, boolean callEnabled, boolean smsEnabled, String message) {
        if (numbers == null) return;
        SmsManager smsManager = SmsManager.getDefault();
        for (int i = 0; i < numbers.length(); i++) {
            String num = numbers.optString(i, "").trim();
            if (num.isEmpty()) continue;
            try {
                if (smsEnabled) {
                    smsManager.sendTextMessage(num, null, message, null, null);
                }
                if (callEnabled) {
                    Intent callIntent = new Intent(Intent.ACTION_CALL);
                    callIntent.setData(Uri.parse("tel:" + num));
                    callIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(callIntent);
                    Thread.sleep(25000);
                }
            } catch (Exception ignored) {}
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
