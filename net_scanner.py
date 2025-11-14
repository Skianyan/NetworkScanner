import sys
from datetime import datetime
from dataclasses import dataclass, field
import socket
import ipaddress
import nettest
from PyQt5 import QtWidgets, QtCore, QtGui
from scapy.all import arping, conf  # type: ignore

## class for scan data.
@dataclass
class Device:
    ip: str
    mac: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    online: bool = True
    misses: int = 0  # consecutive scans not seen
    name: str = ""   # reverse-DNS or fallback to IP when rendering

## define 
def current_ipv4_network() -> ipaddress.IPv4Network:
    try:
        gw = nettest.gateways().get('default', {}).get(nettest.AF_INET)
        if gw:
            _, iface = gw
        else:
            _, _, iface = conf.route.route("0.0.0.0")
        addrs = nettest.ifaddresses(iface)[nettest.AF_INET][0]
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
    # Keep this quick; reverse DNS only. If none, return "" and UI will show IP.
    try:
        # gethostbyaddr has no per-call timeout; set global for worker thread.
        orig_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host or ""
        finally:
            socket.setdefaulttimeout(orig_to)
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


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LAN Scanner")
        self.resize(980, 520)

        self.devices: dict[str, Device] = {}
        self.scanning = False
        self.auto_timer = QtCore.QTimer(self)
        self.auto_timer.timeout.connect(self.start_scan)

        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        v = QtWidgets.QVBoxLayout(root)

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

        # Columns: Name, IP, MAC, First seen, Last seen, Status
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Name", "IP", "MAC", "First seen (UTC)", "Last seen (UTC)", "Status"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        v.addWidget(self.table)

        self.network = current_ipv4_network()
        self.lblSubnet.setText(f"Subnet: {self.network.with_prefixlen}")

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
        now = datetime.datetime.now(datetime.UTC)
        found_ips = set(ip for ip, _ in results)

        # Update or add seen devices
        for ip, mac in results:
            if ip in self.devices:
                d = self.devices[ip]
                # If MAC changed
                mac_changed = d.mac.lower() != mac.lower()
                d.mac = mac
                d.last_seen = now
                d.online = True
                d.misses = 0
                # Refresh name if empty
                if not d.name:
                    d.name = resolve_name(ip)
            else:
                name = resolve_name(ip)
                self.devices[ip] = Device(
                    ip=ip, mac=mac, first_seen=now, last_seen=now,
                    online=True, misses=0, name=name
                )

        # Increment misses for unseen devices and mark offline
        to_delete = []
        for ip, dev in list(self.devices.items()):
            if ip not in found_ips:
                dev.online = False
                dev.misses += 1
                # Remove after two consecutive misses (third scan total)
                if dev.misses >= 2:
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
        # Sort by IP
        rows = sorted(self.devices.values(), key=lambda d: tuple(int(x) for x in d.ip.split(".")))
        self.table.setRowCount(len(rows))
        for r, dev in enumerate(rows):
            display_name = dev.name if dev.name else dev.ip
            cells = [
                QtWidgets.QTableWidgetItem(display_name),
                QtWidgets.QTableWidgetItem(dev.ip),
                QtWidgets.QTableWidgetItem(dev.mac),
                QtWidgets.QTableWidgetItem(dev.first_seen.strftime("%Y-%m-%d %H:%M:%S")),
                QtWidgets.QTableWidgetItem(dev.last_seen.strftime("%Y-%m-%d %H:%M:%S")),
                QtWidgets.QTableWidgetItem("online" if dev.online else f"offline - misses {dev.misses}"),
            ]
            for c, itm in enumerate(cells):
                # Grey out if offline
                if not dev.online:
                    itm.setForeground(QtGui.QBrush(QtGui.QColor("gray")))
                else:
                    itm.setForeground(QtGui.QBrush())
                # Monospace for IP/MAC
                if c in (1, 2):
                    f = itm.font()
                    f.setFamily("Consolas")
                    itm.setFont(f)
                self.table.setItem(r, c, itm)


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
