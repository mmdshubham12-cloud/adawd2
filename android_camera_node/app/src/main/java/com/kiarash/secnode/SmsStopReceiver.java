package com.kiarash.secnode;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

@SuppressWarnings("deprecation")
public class SmsStopReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle bundle = intent.getExtras();
        if (bundle == null) return;
        Object[] pdus = (Object[]) bundle.get("pdus");
        if (pdus == null) return;

        for (Object pdu : pdus) {
            SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdu);
            final String sender = msg.getOriginatingAddress();
            final String body = msg.getMessageBody();

            if (body != null && (body.contains("توقف آلارم") || body.contains("قطع هشدار"))) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            DatagramSocket socket = new DatagramSocket();
                            socket.setBroadcast(true);
                            byte[] data = ("SMS_STOP_ALARM:" + sender).getBytes("UTF-8");
                            DatagramPacket packet = new DatagramPacket(
                                data, data.length, InetAddress.getByName("255.255.255.255"), 47822);
                            socket.send(packet);
                            socket.close();
                        } catch (Exception ignored) {}
                    }
                }).start();
            }
        }
    }
}
