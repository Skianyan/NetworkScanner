import sys
from datetime import datetime
from dataclasses import dataclass, field
import socket
import ipaddress
import netifaces
from PyQt5 import QtWidgets, QtCore, QtGui
from scapy.all import arping, conf  # type: ignore

# Local OUI database
from manuf import manuf
_OUI = manuf.MacParser(update=False)


@dataclass
class Device:
    ip: str
    mac: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    online: bool = True
    misses: int = 0            # consecutive scans not seen
    name: str = ""             # reverse DNS
    vendor: str = ""           # OUI manufacturer if found


def current_ipv4_network() -> ipaddress.IPv4Network:
    try:
        gw = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
        if gw:
            _, iface = gw
        else:
            _, _, iface = conf.route.route("0.0.0.0")
        addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        ip = addrs["addr"]
        mask = addrs["netmask"]
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    except Exception:
        src = conf.route.route("0.0.0.0")[1]
        return ipaddress.IPv4Network(f"{src}/24", strict=False)


def arp_scan(cidr: str, timeout: int = 2):
    ans, _ = arping(cidr, timeout=timeout, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in ans]


def resolve_name(ip: str) -> str:
    try:
        orig_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host or ""
        finally:
            socket.setdefaulttimeout(orig_to)
    except Exception:
        return ""


def _normalize_mac(mac: str) -> str:
    mac = mac.strip().replace("-", ":").lower()
    if ":" not in mac and len(mac) == 12:
        mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def _is_locally_administered(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b10)
    except Exception:
        return False


def lookup_vendor(mac: str) -> str:
    mac_n = _normalize_mac(mac)
    if not mac_n or _is_locally_administered(mac_n):
        return ""
    try:
        return _OUI.get_manuf(mac_n) or ""
    except Exception:
        return ""


class ScannerWorker(QtCore.QObject):
    finished = QtCore.pyqtSignal(list)  # list[(ip, mac)]
    error = QtCore.pyqtSignal(str)

    def __init__(self, cidr: str, timeout: int = 2):
        super().__init__()
        self.cidr = cidr
        self.timeout = timeout

    @QtCore.pyqtSlot()
    def run(self):
        try:
            self.finished.emit(arp_scan(self.cidr, self.timeout))
        except Exception as e:
            self.error.emit(str(e))

## QTPy Main window UI
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner v1")
        self.resize(1040, 540)

        self.devices: dict[str, Device] = {}
        self.scanning = False
        self.auto_timer = QtCore.QTimer(self)
        self.auto_timer.timeout.connect(self.start_scan)

        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        v = QtWidgets.QVBoxLayout(root)

        # Controls
        ctrl = QtWidgets.QHBoxLayout()
        self.lblSubnet = QtWidgets.QLabel("Subnet: resolving...")
        self.btnScan = QtWidgets.QPushButton("Scan now")
        self.btnScan.clicked.connect(self.start_scan)
        self.spnInterval = QtWidgets.QSpinBox()
        self.spnInterval.setRange(5, 3600)
        self.spnInterval.setValue(30)
        self.chkAuto = QtWidgets.QCheckBox("Auto-scan every (s)")
        self.chkAuto.stateChanged.connect(self.toggle_auto)

        ctrl.addWidget(self.lblSubnet)
        ctrl.addStretch(1)
        ctrl.addWidget(self.chkAuto)
        ctrl.addWidget(self.spnInterval)
        ctrl.addWidget(self.btnScan)
        v.addLayout(ctrl)

        # Table: State, Name, IP, MAC, Manufacturer, First seen, Last seen
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["State", "Name", "IP", "MAC", "Manufacturer", "First seen (UTC)", "Last seen (UTC)"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        v.addWidget(self.table)
        self.table.setColumnWidth(0, 48)  # compact State column
        self.table.setColumnWidth(2, 144)
        self.table.setColumnWidth(3, 144)
        self.table.setColumnWidth(4, 144)
        self.table.setColumnWidth(5, 144)

        self.network = current_ipv4_network()
        self.lblSubnet.setText(f"Subnet: {self.network.with_prefixlen}")

        # Status icons
        self.icon_green = self._make_color_icon(QtGui.QColor(0, 170, 0))
        self.icon_grey = self._make_color_icon(QtGui.QColor(130, 130, 130))

    def _make_color_icon(self, color: QtGui.QColor, size: int = 14) -> QtGui.QIcon:
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(QtGui.QPen(color))
        p.setBrush(QtGui.QBrush(color))
        rect = QtCore.QRectF(1, 1, size - 2, size - 2)
        p.drawRoundedRect(rect, 3, 3)
        p.end()
        return QtGui.QIcon(pm)

    def toggle_auto(self, state: int):
        if state == QtCore.Qt.Checked:
            self.auto_timer.start(self.spnInterval.value() * 1000)
            self.btnScan.setEnabled(False)
        else:
            self.auto_timer.stop()
            self.btnScan.setEnabled(True)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.statusBar().showMessage("Scanning...")
        self.btnScan.setEnabled(False)

        self.thread = QtCore.QThread()
        self.worker = ScannerWorker(str(self.network))
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @QtCore.pyqtSlot(list)
    def on_scan_finished(self, results: list):
        now = datetime.utcnow()
        found_ips = set(ip for ip, _ in results)

        # Update/add seen devices
        for ip, mac in results:
            mac_n = _normalize_mac(mac)
            if ip in self.devices:
                d = self.devices[ip]
                mac_changed = d.mac.lower() != mac_n.lower()
                d.mac = mac_n
                d.last_seen = now
                d.online = True
                d.misses = 0
                if not d.name:
                    d.name = resolve_name(ip)
                if mac_changed or not d.vendor:
                    d.vendor = lookup_vendor(mac_n)
            else:
                self.devices[ip] = Device(
                    ip=ip,
                    mac=mac_n,
                    first_seen=now,
                    last_seen=now,
                    online=True,
                    misses=0,
                    name=resolve_name(ip),
                    vendor=lookup_vendor(mac_n),
                )

        # Increment misses for unseen devices; prune after second miss
        to_delete = []
        for ip, dev in list(self.devices.items()):
            if ip not in found_ips:
                dev.online = False
                dev.misses += 1
                if dev.misses >= 2:  # third scan not seen -> remove
                    to_delete.append(ip)
        for ip in to_delete:
            del self.devices[ip]

        self.refresh_table()
        self.statusBar().showMessage(f"Scan complete. Found {len(results)} active.", 2500)
        self.scanning = False
        self.btnScan.setEnabled(not self.chkAuto.isChecked())

    @QtCore.pyqtSlot(str)
    def on_scan_error(self, msg: str):
        QtWidgets.QMessageBox.critical(self, "Scan error", msg)
        self.statusBar().clearMessage()
        self.scanning = False
        self.btnScan.setEnabled(True)

    def refresh_table(self):
        rows = sorted(self.devices.values(), key=lambda d: tuple(int(x) for x in d.ip.split(".")))
        self.table.setRowCount(len(rows))
        for r, dev in enumerate(rows):
            display_name = dev.name if dev.name else dev.ip

            # State icon
            state_item = QtWidgets.QTableWidgetItem()
            if dev.online:
                state_item.setIcon(self.icon_green)
                state_item.setToolTip("Online")
            elif dev.misses == 1:
                state_item.setIcon(self.icon_grey)
                state_item.setToolTip("Did not respond on the second scan")
            else:
                state_item.setToolTip("Offline")

            name_item = QtWidgets.QTableWidgetItem(display_name)
            ip_item = QtWidgets.QTableWidgetItem(dev.ip)
            mac_item = QtWidgets.QTableWidgetItem(dev.mac)
            vendor_item = QtWidgets.QTableWidgetItem(dev.vendor)
            first_item = QtWidgets.QTableWidgetItem(dev.first_seen.strftime("%Y-%m-%d %H:%M:%S"))
            last_item = QtWidgets.QTableWidgetItem(dev.last_seen.strftime("%Y-%m-%d %H:%M:%S"))

            # Grey text for offline rows
            items = [name_item, ip_item, mac_item, vendor_item, first_item, last_item]
            if not dev.online:
                for itm in items:
                    itm.setForeground(QtGui.QBrush(QtGui.QColor("gray")))
            else:
                for itm in items:
                    itm.setForeground(QtGui.QBrush())

            # Monospace for IP/MAC
            for itm in (ip_item, mac_item):
                f = itm.font()
                f.setFamily("Consolas")
                itm.setFont(f)

            # Insert into table (no Status column now)
            self.table.setItem(r, 0, state_item)
            self.table.setItem(r, 1, name_item)
            self.table.setItem(r, 2, ip_item)
            self.table.setItem(r, 3, mac_item)
            self.table.setItem(r, 4, vendor_item)
            self.table.setItem(r, 5, first_item)
            self.table.setItem(r, 6, last_item)


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
