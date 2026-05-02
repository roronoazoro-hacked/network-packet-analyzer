import numpy as np
import threading
import time
from collections import deque
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, baseline_duration=120, contamination=0.05):
        """
        baseline_duration : seconds to collect normal traffic before training
        contamination     : expected % of anomalies (5% default)
        """
        self.baseline_duration = baseline_duration
        self.contamination     = contamination
        self.model             = None
        self.is_trained        = False
        self.is_collecting     = True
        self.training_data     = []
        self.lock              = threading.Lock()
        self.start_time        = time.time()
        self.anomaly_count     = 0
        self.total_checked     = 0
        self.status            = "Collecting baseline..."

    def extract_features(self, packet):
        """
        Convert a parsed packet dict into a numeric feature vector.
        Features: dst_port, proto_num, is_private_dst, packet_size_approx
        """
        proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3, "OTHER": 0}

        proto_num    = proto_map.get(packet.get("proto", "OTHER"), 0)
        dst_port     = int(packet.get("dst_port", 0))
        src_private  = 1 if self._is_private(packet.get("src", "")) else 0
        dst_private  = 1 if self._is_private(packet.get("dst", "")) else 0
        level_map    = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        level_num    = level_map.get(packet.get("level", "NORMAL"), 0)

        return [proto_num, dst_port, src_private, dst_private, level_num]

    def _is_private(self, ip):
        private = ["10.", "192.168.", "127.", "172.16.", "172.17.",
                   "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                   "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                   "172.28.", "172.29.", "172.30.", "172.31."]
        return any(ip.startswith(r) for r in private)

    def add_packet(self, packet):
        """Add packet to training data or check for anomaly."""
        features = self.extract_features(packet)

        with self.lock:
            elapsed = time.time() - self.start_time

            # Phase 1 — collect baseline
            if self.is_collecting:
                self.training_data.append(features)
                remaining = int(self.baseline_duration - elapsed)
                self.status = f"Collecting baseline... {remaining}s left ({len(self.training_data)} packets)"

                if elapsed >= self.baseline_duration and len(self.training_data) >= 50:
                    self.is_collecting = False
                    self._train()
                return None

            # Phase 2 — detect anomalies
            if self.is_trained:
                return self._predict(features, packet)

        return None

    def _train(self):
        """Train the Isolation Forest on collected baseline data."""
        try:
            X = np.array(self.training_data)
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self.model.fit(X)
            self.is_trained = True
            self.status = f"Trained on {len(self.training_data)} packets — watching for anomalies"
            print(f"[ML] Isolation Forest trained on {len(self.training_data)} packets")
        except Exception as e:
            self.status = f"Training failed: {e}"
            print(f"[ML ERROR] {e}")

    def _predict(self, features, packet):
        """Check if a packet is anomalous. Returns alert dict or None."""
        try:
            self.total_checked += 1
            X      = np.array([features])
            result = self.model.predict(X)[0]
            score  = self.model.score_samples(X)[0]

            # -1 = anomaly, 1 = normal
            if result == -1:
                self.anomaly_count += 1
                confidence = int((1 - (score + 0.5)) * 100)
                confidence = max(0, min(100, confidence))

                return {
                    "src":        packet.get("src", ""),
                    "dst":        packet.get("dst", ""),
                    "proto":      packet.get("proto", ""),
                    "dst_port":   packet.get("dst_port", 0),
                    "confidence": confidence,
                    "reason":     f"Anomalous {packet.get('proto','')} traffic pattern detected",
                }
        except Exception:
            pass
        return None

    def get_status(self):
        with self.lock:
            return {
                "status":        self.status,
                "is_trained":    self.is_trained,
                "is_collecting": self.is_collecting,
                "anomalies":     self.anomaly_count,
                "total_checked": self.total_checked,
                "training_size": len(self.training_data),
            }

    def retrain(self):
        """Reset and retrain from scratch."""
        with self.lock:
            self.model         = None
            self.is_trained    = False
            self.is_collecting = True
            self.training_data = []
            self.start_time    = time.time()
            self.anomaly_count = 0
            self.total_checked = 0
            self.status        = "Retraining — collecting baseline..."
        print("[ML] Retraining started")