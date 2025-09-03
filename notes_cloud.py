# === Project Yggdrasil: Railroad Node — Final Iron ===

import platform
import subprocess
import datetime
import random

class RailroadNode:
    def __init__(self):
        self.os_name = self.detect_os()
        self.runtimes = self.detect_runtimes()
        self.train_logs = []
        self.pos_transactions = []
        self.offline_cache = []
        self.fra_compliance = True
        self.union_compliance = True
        self.osha_compliance = True
        self.financial_status = True

    def log_to_cpa_chain(self, message):
        timestamp = datetime.datetime.utcnow().isoformat()
        print(f"[CPA LOG] {timestamp} - {message}")

    def witness_mesh_sign(self, message):
        print(f"[WITNESS MESH SIGNED] {message}")

    def detect_os(self):
        os_name = platform.system()
        self.log_to_cpa_chain(f"Railroad Node OS: {os_name}")
        self.witness_mesh_sign("OS Detection Signed")
        return os_name

    def check_runtime(self, command):
        try:
            output = subprocess.check_output(command, shell=True).decode().strip()
            return output
        except:
            return None

    def detect_runtimes(self):
        runtimes = {
            "Python": self.check_runtime("python --version"),
            "Node.js": self.check_runtime("node --version"),
            "Java": self.check_runtime("java -version"),
            "Go": self.check_runtime("go version"),
            "Ruby": self.check_runtime("ruby --version"),
            "PowerShell": self.check_runtime("powershell -command \"$PSVersionTable\"") if self.os_name == "Windows" else None
        }
        self.log_to_cpa_chain(f"Railroad Runtimes: {runtimes}")
        self.witness_mesh_sign("Runtime Detection Signed")
        return runtimes

    def log_train_movement(self, train_id, engineer_id, union_id, cargo_manifest, departure, arrival):
        log_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "train_id": train_id,
            "engineer_id": engineer_id,
            "union_id": union_id,
            "cargo": cargo_manifest,
            "departure": departure,
            "arrival": arrival
        }
        self.train_logs.append(log_entry)
        self.log_to_cpa_chain(f"Train Movement Logged: {log_entry}")
        self.witness_mesh_sign("Train Movement Signed")

    def record_pos_transaction(self, transaction):
        self.pos_transactions.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "transaction": transaction
        })
        self.log_to_cpa_chain(f"POS Transaction Logged: {transaction}")
        self.witness_mesh_sign("POS Transaction Signed")

    def verify_fra_compliance(self):
        if not self.fra_compliance:
            self.log_to_cpa_chain("FRA Violation! Railroad Node Locked.")
            self.witness_mesh_sign("FRA Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("FRA Compliance Verified")
            self.witness_mesh_sign("FRA OK Signed")

    def verify_union_compliance(self):
        if not self.union_compliance:
            self.log_to_cpa_chain("Union Agreement Violation! Railroad Node Locked.")
            self.witness_mesh_sign("Union Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("Union Compliance Verified")
            self.witness_mesh_sign("Union OK Signed")

    def verify_osha_compliance(self):
        if not self.osha_compliance:
            self.log_to_cpa_chain("OSHA Violation! Railroad Node Locked.")
            self.witness_mesh_sign("OSHA Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("OSHA Compliance Verified")
            self.witness_mesh_sign("OSHA OK Signed")

    def verify_financial(self):
        if not self.financial_status:
            self.log_to_cpa_chain("Financial Discrepancy! Railroad Node Locked.")
            self.witness_mesh_sign("Financial Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("Financial Node Verified")
            self.witness_mesh_sign("Financial OK Signed")

    def lock_node(self):
        self.log_to_cpa_chain("Railroad Node Disabled Due to Compliance Breach")
        self.witness_mesh_sign("Node Lockdown Signed")

    def offline_cache_log(self, log):
        self.offline_cache.append(log)
        self.log_to_cpa_chain(f"Log Cached Offline: {log}")

    def push_offline_cache(self):
        if self.offline_cache:
            for entry in self.offline_cache:
                if entry.get("type") == "movement":
                    self.log_train_movement(**entry["data"])
                elif entry.get("type") == "transaction":
                    self.record_pos_transaction(entry["data"])
            self.offline_cache.clear()
            self.witness_mesh_sign("Offline Cache Synced Signed")

if __name__ == "__main__":
    # === DEMO ===

    rr_node = RailroadNode()

    # OS/runtime detection happens on init

    # Log train movement
    rr_node.log_train_movement(
        train_id="RR-900",
        engineer_id="ENG-222",
        union_id="BLE-LOCAL-1",
        cargo_manifest={"cars": 40, "freight": "Crude Oil"},
        departure="Houston",
        arrival="St. Louis"
    )

    # POS transaction for freight billing
    rr_node.record_pos_transaction({"invoice_id": "INV-452", "amount": 12000.00})

    # Compliance checks
    rr_node.verify_fra_compliance()
    rr_node.verify_union_compliance()
    rr_node.verify_osha_compliance()
    rr_node.verify_financial()

    # Offline scenario
    rr_node.offline_cache_log({
        "type": "movement",
        "data": {
            "train_id": "RR-901",
            "engineer_id": "ENG-333",
            "union_id": "BLE-LOCAL-2",
            "cargo_manifest": {"cars": 60, "freight": "Lumber"},
            "departure": "Portland",
            "arrival": "Denver"
        }
    })
    rr_node.push_offline_cache()




# === Project Yggdrasil: Logistics Node Core ===

import platform
import subprocess
import datetime
import random

class LogisticsNode:
    def __init__(self):
        self.os_name = self.detect_os()
        self.runtimes = self.detect_runtimes()
        self.shipment_logs = []
        self.eld_status = True
        self.compliance_status = True
        self.offline_cache = []

    def log_to_cpa_chain(self, message):
        timestamp = datetime.datetime.utcnow().isoformat()
        print(f"[CPA LOG] {timestamp} - {message}")

    def witness_mesh_sign(self, message):
        print(f"[WITNESS MESH SIGNED] {message}")

    def detect_os(self):
        os_name = platform.system()
        self.log_to_cpa_chain(f"Logistics Node OS: {os_name}")
        self.witness_mesh_sign("OS Detection Signed")
        return os_name

    def check_runtime(self, command):
        try:
            output = subprocess.check_output(command, shell=True).decode().strip()
            return output
        except:
            return None

    def detect_runtimes(self):
        runtimes = {
            "Python": self.check_runtime("python --version"),
            "Node.js": self.check_runtime("node --version"),
            "Java": self.check_runtime("java -version"),
            "Go": self.check_runtime("go version"),
            "Ruby": self.check_runtime("ruby --version"),
            "PowerShell": self.check_runtime("powershell -command \"$PSVersionTable\"") if self.os_name == "Windows" else None
        }
        self.log_to_cpa_chain(f"Logistics Runtimes: {runtimes}")
        self.witness_mesh_sign("Runtime Detection Signed")
        return runtimes

    def verify_eld_status(self):
        if not self.eld_status:
            self.log_to_cpa_chain("ELD Compliance Violation! Logistics Node Locked.")
            self.witness_mesh_sign("ELD Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("ELD Compliance Verified")
            self.witness_mesh_sign("ELD OK Signed")

    def record_shipment(self, shipment):
        self.shipment_logs.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "shipment": shipment
        })
        self.log_to_cpa_chain(f"Shipment Recorded: {shipment}")
        self.witness_mesh_sign("Shipment Log Signed")

    def broadcast_eld_status(self):
        status = "ELD OK" if self.eld_status else "ELD Non-Compliance"
        self.log_to_cpa_chain(f"Broadcasting ELD Status: {status} to Core & Retail Node")
        self.witness_mesh_sign("ELD Broadcast Signed")

    def verify_compliance(self):
        if not self.compliance_status:
            self.log_to_cpa_chain("Logistics Compliance Violation! Node Locked.")
            self.witness_mesh_sign("Compliance Lockdown Signed")
            self.lock_node()
        else:
            self.log_to_cpa_chain("Logistics Compliance Verified")
            self.witness_mesh_sign("Compliance OK Signed")

    def lock_node(self):
        self.log_to_cpa_chain("Logistics Node Disabled Due to Compliance Breach")
        self.witness_mesh_sign("Node Lockdown Signed")

    def offline_cache_shipment(self, shipment):
        self.offline_cache.append(shipment)
        self.log_to_cpa_chain(f"Shipment Cached Offline: {shipment}")

    def push_offline_cache(self):
        if self.offline_cache:
            for shipment in self.offline_cache:
                self.record_shipment(shipment)
            self.offline_cache.clear()
            self.witness_mesh_sign("Offline Shipment Sync Signed")

if __name__ == "__main__":
    # === DEMO ===

    logistics = LogisticsNode()

    # OS/Runtime detection happens on init

    # Record a shipment
    logistics.record_shipment({
        "truck_id": "TRK-007",
        "driver_id": "DRV-123",
        "route_miles": 450,
        "fuel_used": 75
    })

    # Broadcast ELD status
    logistics.broadcast_eld_status()

    # Verify ELD status
    logistics.verify_eld_status()

    # Compliance check
    logistics.verify_compliance()

    # Offline scenario
    logistics.offline_cache_shipment({
        "truck_id": "TRK-008",
        "driver_id": "DRV-456",
        "route_miles": 300,
        "fuel_used": 50
    })
    logistics.push_offline_cache()