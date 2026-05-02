import curses
import threading
from collections import defaultdict, deque
from datetime import datetime


class Dashboard:
    def __init__(self):
        self.packets     = deque(maxlen=100)   # last 100 packets
        self.alerts      = deque(maxlen=20)    # last 20 alerts
        self.stats       = defaultdict(int)    # protocol counts
        self.top_ips     = defaultdict(int)    # IP activity counts
        self.total       = 0
        self.lock        = threading.Lock()
        self.running     = True

    def add_packet(self, pkt):
        """Called from parser for every decoded packet."""
        if not pkt:
            return
        with self.lock:
            self.total += 1
            self.stats[pkt["protocol"]] += 1
            self.top_ips[pkt["src_ip"]] += 1

            # Assign threat level
            if pkt["alert"]:
                pkt["level"] = "CRITICAL"
            elif pkt["protocol"] == "ICMP":
                pkt["level"] = "LOW"
            elif pkt["dst_port"] in (22, 23, 3389, 445, 139):
                pkt["level"] = "HIGH"
            elif pkt["dst_port"] in (80, 8080):
                pkt["level"] = "MEDIUM"
            else:
                pkt["level"] = "NORMAL"

            self.packets.appendleft(pkt)

            if pkt["alert"]:
                self.alerts.appendleft({
                    "time":  pkt["timestamp"],
                    "msg":   pkt["alert"],
                    "src":   pkt["src_ip"],
                })

    def run(self, stdscr):
        """Main curses render loop."""
        curses.curs_set(0)
        stdscr.nodelay(True)

        # Color pairs
        curses.init_pair(1, curses.COLOR_GREEN,   curses.COLOR_BLACK)  # NORMAL
        curses.init_pair(2, curses.COLOR_YELLOW,  curses.COLOR_BLACK)  # MEDIUM
        curses.init_pair(3, curses.COLOR_RED,     curses.COLOR_BLACK)  # HIGH
        curses.init_pair(4, curses.COLOR_WHITE,   curses.COLOR_RED)    # CRITICAL
        curses.init_pair(5, curses.COLOR_CYAN,    curses.COLOR_BLACK)  # headers
        curses.init_pair(6, curses.COLOR_BLACK,   curses.COLOR_WHITE)  # title bar
        curses.init_pair(7, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # LOW/ICMP

        while self.running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()

                self._draw_titlebar(stdscr, w)
                self._draw_stats(stdscr, w)
                self._draw_packets(stdscr, h, w)
                self._draw_alerts(stdscr, h, w)
                self._draw_top_ips(stdscr, h, w)
                self._draw_footer(stdscr, h, w)

                stdscr.refresh()
                curses.napms(300)

                key = stdscr.getch()
                if key == ord('q'):
                    self.running = False

            except curses.error:
                pass

    def _draw_titlebar(self, s, w):
        title = " Network Packet Analyzer Dashboard  |  Press Q to quit "
        s.attron(curses.color_pair(6) | curses.A_BOLD)
        s.addstr(0, 0, title.center(w - 1))
        s.attroff(curses.color_pair(6) | curses.A_BOLD)

    def _draw_stats(self, s, w):
        with self.lock:
            tcp   = self.stats.get("TCP",     0)
            udp   = self.stats.get("UDP",     0)
            icmp  = self.stats.get("ICMP",    0)
            total = self.total
            alrts = len(self.alerts)

        s.attron(curses.color_pair(5) | curses.A_BOLD)
        s.addstr(2, 2, "LIVE STATS")
        s.attroff(curses.color_pair(5) | curses.A_BOLD)

        stats_line = (
            f"  Total: {total}"
            f"   TCP: {tcp}"
            f"   UDP: {udp}"
            f"   ICMP: {icmp}"
            f"   Alerts: {alrts}"
        )
        color = curses.color_pair(3) if alrts > 0 else curses.color_pair(1)
        s.attron(color)
        s.addstr(3, 2, stats_line[:w - 4])
        s.attroff(color)

        # Divider
        s.attron(curses.color_pair(5))
        s.addstr(4, 0, "─" * (w - 1))
        s.attroff(curses.color_pair(5))

    def _draw_packets(self, s, h, w):
        feed_w = w - 36          # left panel width
        s.attron(curses.color_pair(5) | curses.A_BOLD)
        s.addstr(5, 2, "LIVE PACKET FEED")
        s.attroff(curses.color_pair(5) | curses.A_BOLD)

        level_colors = {
            "CRITICAL": curses.color_pair(4) | curses.A_BOLD,
            "HIGH":     curses.color_pair(3) | curses.A_BOLD,
            "MEDIUM":   curses.color_pair(2),
            "LOW":      curses.color_pair(7),
            "NORMAL":   curses.color_pair(1),
        }
        level_tag = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[!! ]",
            "MEDIUM":   "[ ! ]",
            "LOW":      "[   ]",
            "NORMAL":   "[   ]",
        }

        max_rows = h - 12
        with self.lock:
            pkts = list(self.packets)[:max_rows]

        for i, pkt in enumerate(pkts):
            row = 6 + i
            if row >= h - 6:
                break

            tag   = level_tag.get(pkt["level"], "[   ]")
            proto = f"{pkt['protocol']:5s}"
            line  = (
                f"{tag} {pkt['timestamp']}  "
                f"{proto}  "
                f"{pkt['src_ip']:>15} -> {pkt['dst_ip']:<15}"
                f"  {pkt['info']}"
            )
            color = level_colors.get(pkt["level"], curses.color_pair(1))
            try:
                s.attron(color)
                s.addstr(row, 2, line[:feed_w - 2])
                s.attroff(color)
            except curses.error:
                pass

    def _draw_alerts(self, s, h, w):
        col = w - 34
        s.attron(curses.color_pair(5) | curses.A_BOLD)
        s.addstr(5, col, "ALERTS")
        s.attroff(curses.color_pair(5) | curses.A_BOLD)

        with self.lock:
            alerts = list(self.alerts)[:10]

        if not alerts:
            s.attron(curses.color_pair(1))
            s.addstr(6, col, "No alerts yet")
            s.attroff(curses.color_pair(1))
        else:
            for i, a in enumerate(alerts):
                row = 6 + i * 2
                if row >= h - 8:
                    break
                try:
                    s.attron(curses.color_pair(3) | curses.A_BOLD)
                    s.addstr(row,     col, f"[!] {a['src']}"[:32])
                    s.attroff(curses.color_pair(3) | curses.A_BOLD)
                    s.attron(curses.color_pair(2))
                    s.addstr(row + 1, col, f"    {a['msg']}"[:32])
                    s.attroff(curses.color_pair(2))
                except curses.error:
                    pass

    def _draw_top_ips(self, s, h, w):
        col = w - 34
        row = h - 10
        s.attron(curses.color_pair(5) | curses.A_BOLD)
        s.addstr(row, col, "TOP TALKERS")
        s.attroff(curses.color_pair(5) | curses.A_BOLD)

        with self.lock:
            top = sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)[:5]

        for i, (ip, count) in enumerate(top):
            try:
                s.attron(curses.color_pair(2))
                s.addstr(row + 1 + i, col, f"  {ip:<18} {count:>4}"[:32])
                s.attroff(curses.color_pair(2))
            except curses.error:
                pass

    def _draw_footer(self, s, h, w):
        legend = (
            " [!!!] CRITICAL   [!! ] HIGH   [ ! ] MEDIUM"
            "   [   ] NORMAL/LOW   Q = quit "
        )
        s.attron(curses.color_pair(6))
        try:
            s.addstr(h - 1, 0, legend.center(w - 1))
        except curses.error:
            pass
        s.attroff(curses.color_pair(6))