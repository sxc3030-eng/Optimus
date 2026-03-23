"""
NetGuard Pro — System Tray (Windows)
Icône dans la barre des tâches en bas à droite
Clic droit : Menu avec options
Double-clic : Ouvrir le dashboard
"""
import sys
import os
import threading
import subprocess
import webbrowser

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
except ImportError:
    print("Installation des dépendances tray...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pystray", "pillow", "--break-system-packages"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw

# ── Créer l'icône NG ──────────────────────────────────────────────────────
def create_icon(color=(77, 159, 255)):
    """Crée une icône 64x64 avec le logo NG"""
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Fond arrondi
    draw.rounded_rectangle([2, 2, 62, 62], radius=12, fill=(15, 15, 19))
    
    # Diagonales NG style X
    r, g, b = color
    draw.line([12, 12, 52, 52], fill=(r, g, b, 255), width=5)
    draw.line([52, 12, 32, 32], fill=(r, g, b, 200), width=4)
    draw.line([32, 32, 12, 52], fill=(r, g, b, 200), width=4)
    
    # Point central lumineux
    draw.ellipse([28, 28, 36, 36], fill=(180, 125, 255, 255))
    
    return img

def create_icon_status(running=True):
    color = (61, 255, 180) if running else (255, 77, 106)
    return create_icon(color)

# ── Dossier du projet ─────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD  = os.path.join(SCRIPT_DIR, "netguard_dashboard.html")
SERVICE    = os.path.join(SCRIPT_DIR, "netguard_service.html")
MAP_FILE   = os.path.join(SCRIPT_DIR, "netguard_map.html")
BACKEND    = os.path.join(SCRIPT_DIR, "netguard.py")

_backend_process = None  # Référence au processus backend lancé

# ── Vérifier si le backend tourne ─────────────────────────────────────────
def is_running():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex(('localhost', 8765))
        s.close()
        return result == 0
    except:
        return False

# ── Actions ───────────────────────────────────────────────────────────────
def open_dashboard(icon, item):
    webbrowser.open(f"file:///{DASHBOARD.replace(os.sep, '/')}")

def open_service_manager(icon, item):
    webbrowser.open(f"file:///{SERVICE.replace(os.sep, '/')}")

def open_map(icon, item):
    webbrowser.open(f"file:///{MAP_FILE.replace(os.sep, '/')}")

def start_backend(icon, item):
    global _backend_process
    if not is_running():
        _backend_process = subprocess.Popen(
            [sys.executable, BACKEND],
            cwd=SCRIPT_DIR,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        update_icon(icon)

def stop_backend(icon, item):
    global _backend_process
    if _backend_process and _backend_process.poll() is None:
        _backend_process.terminate()
        try:
            _backend_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _backend_process.kill()
        _backend_process = None
    update_icon(icon)

def restart_backend(icon, item):
    stop_backend(icon, item)
    import time; time.sleep(1)
    start_backend(icon, item)

def update_icon(icon):
    running = is_running()
    icon.icon  = create_icon_status(running)
    icon.title = f"NetGuard Pro — {'🟢 Actif' if running else '🔴 Arrêté'}"

def quit_tray(icon, item):
    icon.stop()

# ── Polling statut ────────────────────────────────────────────────────────
def status_poller(icon):
    import time
    while True:
        update_icon(icon)
        time.sleep(5)

# ── Main ──────────────────────────────────────────────────────────────────
def main():
    running = is_running()
    
    menu = pystray.Menu(
        item('📊 Ouvrir Dashboard',   open_dashboard, default=True),
        item('🗂 Service Manager',    open_service_manager),
        item('🌍 Carte mondiale',     open_map),
        pystray.Menu.SEPARATOR,
        item('▶ Démarrer NetGuard',  start_backend),
        item('■ Arrêter NetGuard',   stop_backend),
        item('↺ Redémarrer',         restart_backend),
        pystray.Menu.SEPARATOR,
        item('✕ Quitter le tray',    quit_tray),
    )
    
    icon = pystray.Icon(
        name  = "Optimus",
        icon  = create_icon_status(running),
        title = f"NetGuard Pro — {'🟢 Actif' if running else '🔴 Arrêté'}",
        menu  = menu,
    )
    
    # Polling en arrière-plan
    t = threading.Thread(target=status_poller, args=(icon,), daemon=True)
    t.start()
    
    print("NetGuard Pro Tray démarré — icône dans la barre des tâches")
    icon.run()

if __name__ == "__main__":
    main()
