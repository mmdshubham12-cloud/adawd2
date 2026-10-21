import os
import sys
import re
import json
import time
import shutil
import socket
import subprocess
import serial
import serial.tools.list_ports
import threading
import datetime
import jdatetime
import requests
import cv2
import numpy as np
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import customtkinter as ctk
from tkinter import messagebox
from PIL import Image

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import uvicorn

try:
    from ultralytics import YOLO
    YOLO_AVAILABLE = True
except Exception:
    YOLO_AVAILABLE = False

CONFIG_FILE = "config.json"

CAMERA_NODE_PORT = 47821   # Custom non-standard port for Android Camera Node
REMOTE_PANEL_PORT = 49155  # Custom non-standard port for Remote Web Panel
UDP_DISCOVERY_PORT = 47822 # Custom UDP broadcast port

DEFAULT_CONFIG = {
    "first_run_completed": False,
    "storage_path": os.path.abspath("./Recordings"),
    "max_storage_gb": 200.0,
    "record_quality": "720p",
    "camera_ip": "AUTO",
    "camera_port": CAMERA_NODE_PORT,
    "remote_port": REMOTE_PANEL_PORT,
    "arduino_port": "AUTO",
    "bale_bot_token": "",
    "bale_chat_id": "",
    "authorized_numbers": ["+989120000000"],
    "roi_norm": [0.15, 0.15, 0.85, 0.85],
    "schedule_enabled": False,
    "schedule_start": "22:00",
    "schedule_end": "07:00",
    "act_siren_enabled": True,
    "act_bale_enabled": True,
    "act_phone_call_enabled": True,
    "act_sms_enabled": True,
    "confidence_threshold": 0.45,
    "min_confirm_frames": 8
}


def get_resource_path(rel_path: str) -> str:
    """Finds bundled files inside PyInstaller _MEIPASS or current folder."""
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), rel_path),
        os.path.join(os.getcwd(), rel_path),
    ]
    if hasattr(sys, "_MEIPASS"):
        candidates.insert(0, os.path.join(sys._MEIPASS, rel_path))
    for p in candidates:
        if os.path.exists(p):
            return p
    return rel_path


def get_local_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


class SecurityCoreEngine:
    def __init__(self):
        self.config = self.load_config()
        self.logs = deque(maxlen=300)
        self.armed = False
        self.siren_active = False
        self.running = True
        self.camera_connected = False

        self.local_ip = get_local_lan_ip()
        self.public_tunnel_url = "در حال ایجاد لینک اینترنتی..."

        self.latest_frame = None
        self.frame_lock = threading.Lock()

        self.serial_conn = None
        self.serial_lock = threading.Lock()

        self.current_writer = None
        self.current_hour_key = None
        self.last_alert_time = 0

        self.model = None
        if YOLO_AVAILABLE:
            try:
                weights_path = get_resource_path("yolov8n.pt")
                self.model = YOLO(weights_path)
                self.log(f"AI Engine: YOLOv8 loaded offline from {os.path.basename(weights_path)}")
            except Exception as e:
                self.log(f"AI Warning: Could not load YOLO weights ({e})")

        self.fgbg = cv2.createBackgroundSubtractorMOG2(history=500, varThreshold=50, detectShadows=True)
        self.consec_intrusion_frames = 0

    def log(self, msg: str):
        ts = jdatetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}"
        print(entry)
        self.logs.append(entry)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    merged["camera_port"] = CAMERA_NODE_PORT
                    merged["remote_port"] = REMOTE_PANEL_PORT
                    return merged
            except Exception:
                pass
        return DEFAULT_CONFIG.copy()

    def save_config(self):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=4, ensure_ascii=False)
        self.log("Configuration saved.")

    # ---------------- ARDUINO SERIAL ----------------
    def connect_arduino(self):
        with self.serial_lock:
            port = self.config.get("arduino_port", "AUTO")
            if port == "AUTO":
                ports = list(serial.tools.list_ports.comports())
                for p in ports:
                    if "Arduino" in p.description or "CH340" in p.description or "USB" in p.description:
                        port = p.device
                        break
                if port == "AUTO" and ports:
                    port = ports[0].device

            if port and port != "AUTO":
                try:
                    self.serial_conn = serial.Serial(port, 9600, timeout=1)
                    time.sleep(2)
                    self.log(f"Arduino Uno connected on {port}")
                    return True
                except Exception as e:
                    self.log(f"Arduino connection failed on {port}: {e}")
        return False

    def send_arduino_cmd(self, cmd: str):
        with self.serial_lock:
            if self.serial_conn and self.serial_conn.is_open:
                try:
                    self.serial_conn.write((cmd + "\n").encode("utf-8"))
                    return True
                except Exception as e:
                    self.log(f"Arduino write error: {e}")
        return False

    # ---------------- HYBRID LAN AUTO-DISCOVERY (UDP + ACTIVE SUBNET SCANNER) ----------------
    def start_discovery_services(self):
        """Runs both passive UDP listener and active HTTP subnet scanner so dynamic IPs are always found."""
        def udp_listener():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", UDP_DISCOVERY_PORT))
                sock.settimeout(2.0)
            except Exception:
                return
            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    text = data.decode("utf-8", errors="ignore").strip()
                    if text.startswith("KIARASH_CAMERA_NODE:"):
                        port = int(text.split(":")[1])
                        if self.config["camera_ip"] != addr[0] or not self.camera_connected:
                            self.config["camera_ip"] = addr[0]
                            self.config["camera_port"] = port
                            self.log(f"UDP Discovered Android Camera at {addr[0]}:{port}")
                    elif text.startswith("SMS_STOP_ALARM:"):
                        sender = text.split(":", 1)[1]
                        self.handle_sms_stop(sender)
                except socket.timeout:
                    continue
                except Exception:
                    pass

        def active_subnet_scanner():
            while self.running:
                if not self.camera_connected:
                    self.scan_lan_for_camera()
                time.sleep(12)

        threading.Thread(target=udp_listener, daemon=True).start()
        threading.Thread(target=active_subnet_scanner, daemon=True).start()

    def scan_lan_for_camera(self):
        """Scans all 254 IPs in the local subnet on port 47821 in under 1.5 seconds."""
        self.local_ip = get_local_lan_ip()
        parts = self.local_ip.split(".")
        if len(parts) != 4 or self.local_ip == "127.0.0.1":
            return
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

        def probe_ip(ip_addr):
            try:
                r = requests.get(f"http://{ip_addr}:{CAMERA_NODE_PORT}/ping", timeout=0.6)
                if r.status_code == 200 and "KIARASH_CAM_OK" in r.text:
                    return ip_addr
            except Exception:
                pass
            return None

        ips_to_check = [f"{prefix}{i}" for i in range(1, 255) if f"{prefix}{i}" != self.local_ip]
        with ThreadPoolExecutor(max_workers=64) as ex:
            for result in ex.map(probe_ip, ips_to_check):
                if result:
                    if self.config["camera_ip"] != result:
                        self.config["camera_ip"] = result
                        self.config["camera_port"] = CAMERA_NODE_PORT
                        self.save_config()
                    self.log(f"Active Subnet Scanner found Android Camera at {result}:{CAMERA_NODE_PORT}")
                    return result
        return None

    # ---------------- ZERO-VPS CLOUDFLARE TUNNEL FOR REMOTE PHONES ----------------
    def start_remote_tunnel(self):
        def tunnel_worker():
            cf_bin = get_resource_path("cloudflared.exe")
            if not os.path.exists(cf_bin):
                self.public_tunnel_url = "فایل cloudflared.exe یافت نشد (فقط شبکه لوکال فعال است)"
                return
            cmd = [cf_bin, "tunnel", "--url", f"http://127.0.0.1:{REMOTE_PANEL_PORT}", "--no-autoupdate"]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )
                for line in proc.stdout:
                    m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
                    if m:
                        self.public_tunnel_url = m.group(0)
                        self.log(f"Remote Internet Link Ready: {self.public_tunnel_url}")
                        if self.config.get("bale_bot_token") and self.config.get("bale_chat_id"):
                            try:
                                requests.post(
                                    f"https://tapi.bale.ai/bot{self.config['bale_bot_token']}/sendMessage",
                                    json={
                                        "chat_id": self.config["bale_chat_id"],
                                        "text": f"🌐 لینک ورود از راه دور با گوشی (بدون نیاز به آی‌پی استاتیک):\n{self.public_tunnel_url}\n\n🏠 لینک داخل مغازه (وای‌فای):\nhttp://{self.local_ip}:{REMOTE_PANEL_PORT}"
                                    },
                                    timeout=8
                                )
                            except Exception:
                                pass
            except Exception as e:
                self.public_tunnel_url = f"خطا در تانل اینترنتی ({e})"

        threading.Thread(target=tunnel_worker, daemon=True).start()

    def handle_sms_stop(self, sender_number: str):
        auth_list = [n.strip() for n in self.config.get("authorized_numbers", []) if n.strip()]
        matched = any(sender_number.endswith(n[-10:]) for n in auth_list if len(n) >= 10)
        if matched or not auth_list:
            self.log(f"Authorized SMS Stop received from {sender_number}!")
            self.stop_siren(source=f"SMS ({sender_number})")
        else:
            self.log(f"Unauthorized SMS Stop attempt ignored from {sender_number}")

    def trigger_android_emergency_calls(self):
        ip = self.config.get("camera_ip", "AUTO")
        if ip == "AUTO":
            ip = self.scan_lan_for_camera() or "AUTO"
        if ip == "AUTO":
            self.log("Cannot trigger calls: Android Camera Node not discovered on LAN yet.")
            return
        port = CAMERA_NODE_PORT
        numbers = self.config.get("authorized_numbers", [])
        payload = {
            "numbers": numbers,
            "call_enabled": self.config.get("act_phone_call_enabled", True),
            "sms_enabled": self.config.get("act_sms_enabled", True),
            "message": "هشدار امنیتی! ورود غیرمجاز در مغازه تشخیص داده شد."
        }
        try:
            url = f"http://{ip}:{port}/trigger_emergency"
            r = requests.post(url, json=payload, timeout=5)
            self.log(f"Android emergency call/SMS triggered on {ip}:{port} -> {r.status_code}")
        except Exception as e:
            self.log(f"Failed to contact Android Camera Node ({ip}:{port}): {e}")
            self.camera_connected = False

    # ---------------- STORAGE & SHAMSI RECORDING ----------------
    def get_resolution_tuple(self):
        q = self.config.get("record_quality", "720p")
        if q == "1080p":
            return (1920, 1080)
        elif q == "480p":
            return (640, 480)
        return (1280, 720)

    def enforce_storage_quota(self):
        base = self.config["storage_path"]
        os.makedirs(base, exist_ok=True)
        max_bytes = float(self.config.get("max_storage_gb", 200.0)) * (1024 ** 3)

        all_files = []
        total_size = 0
        for root, _, files in os.walk(base):
            for f in files:
                if f.endswith((".mp4", ".avi", ".jpg")):
                    fp = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(fp)
                        mtime = os.path.getmtime(fp)
                        total_size += sz
                        all_files.append((mtime, fp, sz))
                    except Exception:
                        pass

        if total_size > max_bytes:
            all_files.sort(key=lambda x: x[0])
            for mtime, fp, sz in all_files:
                if total_size <= max_bytes * 0.95:
                    break
                try:
                    os.remove(fp)
                    total_size -= sz
                    self.log(f"Quota enforcement: removed old file {os.path.basename(fp)}")
                except Exception:
                    pass

    def write_hourly_frame(self, frame):
        now_j = jdatetime.datetime.now()
        date_folder = now_j.strftime("%Y-%m-%d")
        hour_key = now_j.strftime("%Y-%m-%d_%H")

        day_dir = os.path.join(self.config["storage_path"], date_folder)
        os.makedirs(day_dir, exist_ok=True)
        res = self.get_resolution_tuple()
        resized = cv2.resize(frame, res)

        if self.current_hour_key != hour_key or self.current_writer is None:
            if self.current_writer is not None:
                self.current_writer.release()
            self.enforce_storage_quota()
            filename = f"Rec_{now_j.strftime('%H-00-00')}.mp4"
            full_path = os.path.join(day_dir, filename)
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            self.current_writer = cv2.VideoWriter(full_path, fourcc, 15.0, res)
            self.current_hour_key = hour_key
            self.log(f"Started new 1-hour recording chunk: {date_folder}/{filename}")

        self.current_writer.write(resized)

    # ---------------- AI DETECTION & ANTI-SHADOW ENGINE ----------------
    def check_schedule(self):
        if not self.config.get("schedule_enabled", False):
            return
        now_str = datetime.datetime.now().strftime("%H:%M")
        start = self.config.get("schedule_start", "22:00")
        end = self.config.get("schedule_end", "07:00")
        if start <= end:
            should_arm = start <= now_str < end
        else:
            should_arm = now_str >= start or now_str < end
        if should_arm != self.armed:
            self.armed = should_arm
            self.log(f"Schedule auto-switched Armed state to: {self.armed}")

    def detect_intrusion_in_roi(self, frame):
        h, w = frame.shape[:2]
        rx1, ry1, rx2, ry2 = self.config.get("roi_norm", [0.15, 0.15, 0.85, 0.85])
        x1, y1, x2, y2 = int(rx1 * w), int(ry1 * h), int(rx2 * w), int(ry2 * h)

        color = (0, 0, 255) if self.armed else (0, 255, 0)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)

        fgmask = self.fgbg.apply(frame)
        _, non_shadow_mask = cv2.threshold(fgmask, 200, 255, cv2.THRESH_BINARY)

        intruder_detected = False
        conf_thresh = float(self.config.get("confidence_threshold", 0.45))

        if self.model is not None:
            results = self.model.predict(frame, conf=conf_thresh, verbose=False)
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    if cls_id == 0:
                        bx1, by1, bx2, by2 = map(int, box.xyxy[0])
                        cx, cy = (bx1 + bx2) // 2, (by1 + by2) // 2
                        if x1 <= cx <= x2 and y1 <= cy <= y2:
                            roi_fg = non_shadow_mask[max(0, by1):min(h, by2), max(0, bx1):min(w, bx2)]
                            if roi_fg.size > 0 and (np.count_nonzero(roi_fg) / float(roi_fg.size)) > 0.08:
                                intruder_detected = True
                                cv2.rectangle(frame, (bx1, by1), (bx2, by2), (0, 0, 255), 3)
                                cv2.putText(frame, "INTRUDER", (bx1, max(20, by1 - 10)),
                                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
        else:
            roi_crop = non_shadow_mask[y1:y2, x1:x2]
            kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
            roi_crop = cv2.morphologyEx(roi_crop, cv2.MORPH_OPEN, kernel)
            contours, _ = cv2.findContours(roi_crop, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for cnt in contours:
                if cv2.contourArea(cnt) > 2500:
                    intruder_detected = True
                    break

        if self.armed:
            if intruder_detected:
                self.consec_intrusion_frames += 1
                if self.consec_intrusion_frames >= int(self.config.get("min_confirm_frames", 8)):
                    self.execute_act_phase(frame.copy())
            else:
                self.consec_intrusion_frames = max(0, self.consec_intrusion_frames - 1)
        else:
            self.consec_intrusion_frames = 0

        return frame

    # ---------------- ACT PHASE ----------------
    def execute_act_phase(self, alert_frame):
        now = time.time()
        if now - self.last_alert_time < 30:
            return
        self.last_alert_time = now
        self.log("ALERT! Intrusion confirmed inside security zone. Entering ACT phase!")

        if self.config.get("act_siren_enabled", True):
            self.siren_active = True
            self.send_arduino_cmd("ALARM_ON")
            self.log("ACT [1/4]: Siren activated via Arduino Uno Relay.")

        threading.Thread(target=self._record_and_send_evidence, args=(alert_frame,), daemon=True).start()

        if self.config.get("act_phone_call_enabled", True) or self.config.get("act_sms_enabled", True):
            threading.Thread(target=self.trigger_android_emergency_calls, daemon=True).start()

    def _record_and_send_evidence(self, first_frame):
        now_j = jdatetime.datetime.now()
        date_folder = now_j.strftime("%Y-%m-%d")
        ev_dir = os.path.join(self.config["storage_path"], date_folder, "Events")
        os.makedirs(ev_dir, exist_ok=True)
        stamp = now_j.strftime("%H-%M-%S")

        snap_paths = []
        for i in range(3):
            p = os.path.join(ev_dir, f"Alert_{stamp}_snap{i+1}.jpg")
            with self.frame_lock:
                frm = self.latest_frame.copy() if self.latest_frame is not None else first_frame
            cv2.imwrite(p, frm)
            snap_paths.append(p)
            time.sleep(1.2)

        clip_path = os.path.join(ev_dir, f"Alert_{stamp}_15sec.mp4")
        h, w = first_frame.shape[:2]
        writer = cv2.VideoWriter(clip_path, cv2.VideoWriter_fourcc(*"mp4v"), 15.0, (w, h))
        start_t = time.time()
        while time.time() - start_t < 15.0:
            with self.frame_lock:
                if self.latest_frame is not None:
                    writer.write(self.latest_frame)
            time.sleep(1.0 / 15.0)
        writer.release()
        self.log(f"ACT [2/4]: Saved 3 snapshots and 15s video clip to {ev_dir}")

        if self.config.get("act_bale_enabled", True):
            self.send_to_bale_bot(snap_paths, clip_path)

    def send_to_bale_bot(self, snap_paths, clip_path):
        token = self.config.get("bale_bot_token", "").strip()
        chat_id = self.config.get("bale_chat_id", "").strip()
        if not token or not chat_id:
            self.log("Bale Bot warning: token or chat_id is empty.")
            return

        base_url = f"https://tapi.bale.ai/bot{token}"
        try:
            requests.post(f"{base_url}/sendMessage", json={
                "chat_id": chat_id,
                "text": "🚨 هشدار فوری دزدگیر! تشخیص ورود به محدوده ممنوعه.\nبرای قطع آژیر دستور /stop را بفرستید."
            }, timeout=10)
            for sp in snap_paths:
                with open(sp, "rb") as f:
                    requests.post(f"{base_url}/sendPhoto", data={"chat_id": chat_id}, files={"photo": f}, timeout=15)
            with open(clip_path, "rb") as f:
                requests.post(f"{base_url}/sendVideo", data={"chat_id": chat_id}, files={"video": f}, timeout=30)
            self.log("ACT [3/4]: Sent 3 photos + 15s video clip to Bale Bot.")
        except Exception as e:
            self.log(f"Bale Bot send error: {e}")

    def poll_bale_bot_commands(self):
        last_update_id = 0
        while self.running:
            token = self.config.get("bale_bot_token", "").strip()
            if token:
                try:
                    url = f"https://tapi.bale.ai/bot{token}/getUpdates?offset={last_update_id + 1}"
                    r = requests.get(url, timeout=8)
                    if r.status_code == 200:
                        data = r.json()
                        for item in data.get("result", []):
                            last_update_id = item["update_id"]
                            msg = item.get("message", {})
                            txt = msg.get("text", "").strip()
                            if txt in ["/stop", "قطع هشدار", "توقف آلارم"]:
                                self.stop_siren(source="Bale Bot")
                except Exception:
                    pass
            time.sleep(4)

    def stop_siren(self, source="Manual"):
        self.siren_active = False
        self.send_arduino_cmd("ALARM_OFF")
        self.log(f"Siren stopped via {source}.")

    # ---------------- AUTO DEBUG DIAGNOSTICS ----------------
    def run_auto_debug(self):
        report = []
        try:
            os.makedirs(self.config["storage_path"], exist_ok=True)
            usage = shutil.disk_usage(self.config["storage_path"])
            free_gb = usage.free / (1024 ** 3)
            report.append(f"[OK] Storage Folder Accessible (Free: {free_gb:.1f} GB)")
        except Exception as e:
            report.append(f"[FAIL] Storage Folder Error: {e}")

        if self.send_arduino_cmd("PING"):
            report.append("[OK] Arduino Uno Serial Link Active")
        else:
            report.append("[WARN] Arduino Uno Not Connected")

        found_ip = self.scan_lan_for_camera() or self.config.get("camera_ip", "AUTO")
        try:
            r = requests.get(f"http://{found_ip}:{CAMERA_NODE_PORT}/ping", timeout=2)
            if r.status_code == 200:
                report.append(f"[OK] Android Camera Node Online at {found_ip}:{CAMERA_NODE_PORT}")
            else:
                report.append(f"[WARN] Android Camera Node HTTP {r.status_code}")
        except Exception:
            report.append(f"[WARN] Android Camera Node Unreachable on LAN (Make sure phone is on same Wi-Fi)")

        if self.model is not None:
            report.append("[OK] YOLOv8 + Anti-Shadow Engine Loaded Offline")
        else:
            report.append("[WARN] Using OpenCV MOG2 Fallback")

        report.append(f"[INFO] Local Remote URL: http://{self.local_ip}:{REMOTE_PANEL_PORT}")
        report.append(f"[INFO] Internet Remote URL: {self.public_tunnel_url}")

        for line in report:
            self.log("AutoDebug -> " + line)
        return "\n".join(report)

    # ---------------- VIDEO LOOP ----------------
    def video_capture_loop(self):
        cap = None
        last_source = None
        while self.running:
            self.check_schedule()
            cam_ip = self.config.get("camera_ip", "AUTO")
            if cam_ip == "AUTO":
                frame = np.zeros((720, 1280, 3), dtype=np.uint8)
                cv2.putText(frame, f"Scanning LAN for Android Camera on Port {CAMERA_NODE_PORT}...",
                            (60, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.85, (0, 200, 255), 2)
                self.write_hourly_frame(frame)
                with self.frame_lock:
                    self.latest_frame = frame
                time.sleep(1.0)
                continue

            stream_url = f"http://{cam_ip}:{CAMERA_NODE_PORT}/video"
            if cap is None or last_source != stream_url:
                if cap is not None:
                    cap.release()
                cap = cv2.VideoCapture(stream_url)
                last_source = stream_url

            ret, frame = cap.read()
            if not ret or frame is None:
                self.camera_connected = False
                cap.release()
                cap = None
                frame = np.zeros((720, 1280, 3), dtype=np.uint8)
                cv2.putText(frame, f"Searching/Reconnecting Android Camera ({cam_ip}:{CAMERA_NODE_PORT})...",
                            (50, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 165, 255), 2)
                time.sleep(0.8)
            else:
                self.camera_connected = True
                frame = self.detect_intrusion_in_roi(frame)

            self.write_hourly_frame(frame)
            with self.frame_lock:
                self.latest_frame = frame
            time.sleep(0.03)


engine = SecurityCoreEngine()

# ---------------- FASTAPI REMOTE WEB SERVER (PORT 49155) ----------------
app = FastAPI()
templates = Jinja2Templates(directory=get_resource_path("templates"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
def api_status():
    return {
        "armed": engine.armed,
        "siren_active": engine.siren_active,
        "logs": list(engine.logs)[-30:]
    }


@app.post("/api/arm")
def api_arm(state: int):
    engine.armed = bool(state)
    engine.log(f"Remote App changed Armed state to: {engine.armed}")
    return {"ok": True, "armed": engine.armed}


@app.post("/api/stop_siren")
def api_stop_siren():
    engine.stop_siren(source="Remote App")
    return {"ok": True}


@app.post("/api/sms_webhook")
async def api_sms_webhook(request: Request):
    data = await request.json()
    sender = str(data.get("sender", ""))
    body = str(data.get("body", ""))
    if sender and not engine.camera_connected:
        client_ip = request.client.host if request.client else None
        if client_ip and client_ip != "127.0.0.1":
            engine.config["camera_ip"] = client_ip
    if "توقف آلارم" in body or "قطع هشدار" in body:
        engine.handle_sms_stop(sender)
    return {"ok": True}


@app.post("/api/register_camera")
async def api_register_camera(request: Request):
    """Allows Android Camera Node to directly announce its IP via HTTP."""
    client_ip = request.client.host if request.client else None
    if client_ip and engine.config.get("camera_ip") != client_ip:
        engine.config["camera_ip"] = client_ip
        engine.save_config()
        engine.log(f"Android Camera registered itself from {client_ip}:{CAMERA_NODE_PORT}")
    return {"ok": True}


def mjpeg_generator():
    while engine.running:
        with engine.frame_lock:
            frm = engine.latest_frame
        if frm is not None:
            ret, jpg = cv2.imencode(".jpg", frm, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            if ret:
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpg.tobytes() + b"\r\n")
        time.sleep(0.08)


@app.get("/api/live_stream")
def api_live_stream():
    return StreamingResponse(mjpeg_generator(), media_type="multipart/x-mixed-replace; boundary=frame")


@app.get("/api/recordings/dates")
def api_recording_dates():
    base = engine.config["storage_path"]
    if not os.path.exists(base):
        return {"dates": []}
    dirs = sorted([d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))], reverse=True)
    return {"dates": dirs}


@app.get("/api/recordings/files")
def api_recording_files(date: str):
    day_dir = os.path.join(engine.config["storage_path"], os.path.basename(date))
    if not os.path.exists(day_dir):
        return {"files": []}
    files = sorted([f for f in os.listdir(day_dir) if f.endswith(".mp4")])
    return {"files": files}


@app.get("/api/recordings/stream")
def api_recording_stream(date: str, file: str):
    fp = os.path.join(engine.config["storage_path"], os.path.basename(date), os.path.basename(file))
    if os.path.exists(fp):
        return FileResponse(fp, media_type="video/mp4")
    return JSONResponse({"error": "File not found"}, status_code=404)


# ---------------- MODERN CUSTOMTKINTER WINDOWS GUI ----------------
class SecurityWindowsGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("سیستم هوشمند دزدگیر و نظارت تصویری کیارش (Kiarash Security Core)")
        self.geometry("1240x800")

        if not engine.config.get("first_run_completed", False):
            self.after(200, self.open_first_run_wizard)

        self.build_ui()
        self.update_preview()

    def build_ui(self):
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        left_frame = ctk.CTkFrame(self, corner_radius=12)
        left_frame.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")

        # Remote Access Banner at top of window
        remote_banner = ctk.CTkFrame(left_frame, fg_color="#1e293b", corner_radius=8)
        remote_banner.pack(fill="x", padx=10, pady=(10, 4))

        self.lbl_remote_lan = ctk.CTkLabel(
            remote_banner,
            text=f"ورود با گوشی در وای‌فای مغازه:  http://{engine.local_ip}:{REMOTE_PANEL_PORT}",
            font=("Tahoma", 13, "bold"),
            text_color="#38bdf8"
        )
        self.lbl_remote_lan.pack(anchor="w", padx=12, pady=(6, 2))

        self.lbl_remote_wan = ctk.CTkLabel(
            remote_banner,
            text=f"لینک اینترنتی راه دور (بدون نیاز به آی‌پی استاتیک):  {engine.public_tunnel_url}",
            font=("Tahoma", 12),
            text_color="#4ade80"
        )
        self.lbl_remote_wan.pack(anchor="w", padx=12, pady=(2, 6))

        self.video_label = ctk.CTkLabel(left_frame, text="در حال جستجوی خودکار گوشی دوربین در شبکه...")
        self.video_label.pack(fill="both", expand=True, padx=10, pady=6)

        ctrl_bar = ctk.CTkFrame(left_frame)
        ctrl_bar.pack(fill="x", padx=10, pady=8)

        self.btn_arm = ctk.CTkButton(ctrl_bar, text="فعال‌سازی دزدگیر (ARM)", fg_color="#16a34a", command=self.toggle_arm)
        self.btn_arm.pack(side="left", padx=6, pady=6, expand=True, fill="x")

        self.btn_stop_siren = ctk.CTkButton(ctrl_bar, text="قطع فوری آژیر (STOP SIREN)", fg_color="#dc2626",
                                            command=lambda: engine.stop_siren("Windows GUI"))
        self.btn_stop_siren.pack(side="left", padx=6, pady=6, expand=True, fill="x")

        self.btn_scan = ctk.CTkButton(ctrl_bar, text="جستجوی فوری گوشی دوربین", fg_color="#0284c7",
                                      command=lambda: threading.Thread(target=engine.scan_lan_for_camera, daemon=True).start())
        self.btn_scan.pack(side="left", padx=6, pady=6)

        self.btn_wizard = ctk.CTkButton(ctrl_bar, text="تنظیمات اولیه", command=self.open_first_run_wizard)
        self.btn_wizard.pack(side="left", padx=6, pady=6)

        right_frame = ctk.CTkFrame(self, corner_radius=12)
        right_frame.grid(row=0, column=1, padx=12, pady=12, sticky="nsew")

        ctk.CTkLabel(right_frame, text="مدیریت فاز اکشن (ACT Phase)", font=("Tahoma", 15, "bold")).pack(pady=10)

        self.sw_siren = ctk.CTkSwitch(right_frame, text="آژیر آردوینو (Relay)", command=self.save_switches)
        if engine.config.get("act_siren_enabled", True):
            self.sw_siren.select()
        self.sw_siren.pack(anchor="w", padx=16, pady=4)

        self.sw_bale = ctk.CTkSwitch(right_frame, text="ارسال ۳ عکس و ویدیو ۱۵ ثانیه به بله", command=self.save_switches)
        if engine.config.get("act_bale_enabled", True):
            self.sw_bale.select()
        self.sw_bale.pack(anchor="w", padx=16, pady=4)

        self.sw_call = ctk.CTkSwitch(right_frame, text="تماس تلفنی ترتیبی با گوشی دوربین", command=self.save_switches)
        if engine.config.get("act_phone_call_enabled", True):
            self.sw_call.select()
        self.sw_call.pack(anchor="w", padx=16, pady=4)

        self.sw_sms = ctk.CTkSwitch(right_frame, text="ارسال پیامک هشدار اضطراری", command=self.save_switches)
        if engine.config.get("act_sms_enabled", True):
            self.sw_sms.select()
        self.sw_sms.pack(anchor="w", padx=16, pady=4)

        ctk.CTkLabel(right_frame, text="تست قطعات و اوتو دیباگ", font=("Tahoma", 15, "bold")).pack(pady=(16, 6))

        ctk.CTkButton(right_frame, text="اجرای Auto-Debug کامل", fg_color="#0284c7",
                      command=self.run_autodebug_modal).pack(fill="x", padx=16, pady=4)
        ctk.CTkButton(right_frame, text="تست آژیر آردوینو (1.5 ثانیه)",
                      command=lambda: engine.send_arduino_cmd("TEST_SIREN")).pack(fill="x", padx=16, pady=4)
        ctk.CTkButton(right_frame, text="تست تماس و پیامک گوشی دوربین",
                      command=lambda: threading.Thread(target=engine.trigger_android_emergency_calls, daemon=True).start()).pack(fill="x", padx=16, pady=4)
        ctk.CTkButton(right_frame, text="کپی لینک اینترنتی ریموت", fg_color="#16a34a",
                      command=self.copy_tunnel_url).pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(right_frame, text="لاگ زنده سیستم", font=("Tahoma", 14, "bold")).pack(pady=(14, 4))
        self.log_text = ctk.CTkTextbox(right_frame, height=220)
        self.log_text.pack(fill="both", expand=True, padx=12, pady=8)

    def copy_tunnel_url(self):
        self.clipboard_clear()
        self.clipboard_append(engine.public_tunnel_url)
        messagebox.showinfo("کپی شد", f"لینک ریموت کپی شد:\n{engine.public_tunnel_url}\n\nهمچنین اگر بات بله را تنظیم کرده باشید، لینک جدید هر بار به بله شما پیامک می‌شود.")

    def save_switches(self):
        engine.config["act_siren_enabled"] = bool(self.sw_siren.get())
        engine.config["act_bale_enabled"] = bool(self.sw_bale.get())
        engine.config["act_phone_call_enabled"] = bool(self.sw_call.get())
        engine.config["act_sms_enabled"] = bool(self.sw_sms.get())
        engine.save_config()

    def toggle_arm(self):
        engine.armed = not engine.armed
        engine.log(f"User toggled Armed state to: {engine.armed}")

    def run_autodebug_modal(self):
        res = engine.run_auto_debug()
        messagebox.showinfo("Auto-Debug Report", res)

    def open_first_run_wizard(self):
        win = ctk.CTkToplevel(self)
        win.title("تنظیمات اولیه سیستم امنیتی")
        win.geometry("540x620")
        win.grab_set()

        ctk.CTkLabel(win, text="مسیر ذخیره ویدیوها (تاریخ شمسی):").pack(anchor="w", padx=16, pady=(12, 2))
        ent_path = ctk.CTkEntry(win, width=480)
        ent_path.insert(0, engine.config["storage_path"])
        ent_path.pack(padx=16, pady=4)

        ctk.CTkLabel(win, text="حداکثر حجم مجاز ضبط (گیگابایت):").pack(anchor="w", padx=16, pady=(8, 2))
        ent_quota = ctk.CTkEntry(win, width=480)
        ent_quota.insert(0, str(engine.config["max_storage_gb"]))
        ent_quota.pack(padx=16, pady=4)

        ctk.CTkLabel(win, text="کیفیت ضبط قطعات یک ساعته:").pack(anchor="w", padx=16, pady=(8, 2))
        cmb_q = ctk.CTkOptionMenu(win, values=["1080p", "720p", "480p"])
        cmb_q.set(engine.config.get("record_quality", "720p"))
        cmb_q.pack(padx=16, pady=4, fill="x")

        ctk.CTkLabel(win, text="شماره‌های مجاز تماس و پیامک قطع آژیر (با کاما جدا کنید):").pack(anchor="w", padx=16, pady=(8, 2))
        ent_nums = ctk.CTkEntry(win, width=480)
        ent_nums.insert(0, ",".join(engine.config.get("authorized_numbers", [])))
        ent_nums.pack(padx=16, pady=4)

        ctk.CTkLabel(win, text="توکن بات بله (Bale Bot Token):").pack(anchor="w", padx=16, pady=(8, 2))
        ent_token = ctk.CTkEntry(win, width=480)
        ent_token.insert(0, engine.config.get("bale_bot_token", ""))
        ent_token.pack(padx=16, pady=4)

        ctk.CTkLabel(win, text="چت آیدی بله (Bale Chat ID):").pack(anchor="w", padx=16, pady=(8, 2))
        ent_chat = ctk.CTkEntry(win, width=480)
        ent_chat.insert(0, engine.config.get("bale_chat_id", ""))
        ent_chat.pack(padx=16, pady=4)

        def save_and_close():
            engine.config["storage_path"] = ent_path.get().strip()
            try:
                engine.config["max_storage_gb"] = float(ent_quota.get().strip())
            except Exception:
                engine.config["max_storage_gb"] = 200.0
            engine.config["record_quality"] = cmb_q.get()
            engine.config["authorized_numbers"] = [x.strip() for x in ent_nums.get().split(",") if x.strip()]
            engine.config["bale_bot_token"] = ent_token.get().strip()
            engine.config["bale_chat_id"] = ent_chat.get().strip()
            engine.config["first_run_completed"] = True
            engine.save_config()
            win.destroy()

        ctk.CTkButton(win, text="ذخیره تنظیمات و شروع به کار دائمی", fg_color="#16a34a",
                      command=save_and_close).pack(fill="x", padx=16, pady=20)

    def update_preview(self):
        with engine.frame_lock:
            frm = engine.latest_frame
        if frm is not None:
            rgb = cv2.cvtColor(frm, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb).resize((760, 420))
            ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(760, 420))
            self.video_label.configure(image=ctk_img, text="")

        self.lbl_remote_lan.configure(
            text=f"ورود با گوشی در وای‌فای مغازه:  http://{engine.local_ip}:{REMOTE_PANEL_PORT}  |  دوربین: {engine.config.get('camera_ip')}:{CAMERA_NODE_PORT}"
        )
        self.lbl_remote_wan.configure(
            text=f"لینک اینترنتی راه دور (بدون VPS):  {engine.public_tunnel_url}"
        )

        if engine.armed:
            self.btn_arm.configure(text="دزدگیر فعال است (کلیک برای غیرفعال‌سازی)", fg_color="#dc2626")
        else:
            self.btn_arm.configure(text="فعال‌سازی دزدگیر (ARM)", fg_color="#16a34a")

        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", "\n".join(list(engine.logs)[-25:]))
        self.after(100, self.update_preview)


def start_web_server():
    uvicorn.run(app, host="0.0.0.0", port=REMOTE_PANEL_PORT, log_level="warning")


if __name__ == "__main__":
    engine.connect_arduino()
    engine.start_discovery_services()
    engine.start_remote_tunnel()
    threading.Thread(target=engine.video_capture_loop, daemon=True).start()
    threading.Thread(target=engine.poll_bale_bot_commands, daemon=True).start()
    threading.Thread(target=start_web_server, daemon=True).start()

    gui = SecurityWindowsGUI()
    gui.mainloop()
