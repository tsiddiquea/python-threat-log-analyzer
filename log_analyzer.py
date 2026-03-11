import sys
import re
from collections import defaultdict
from datetime import datetime


# -------------------------------
# CONFIGURATION
# -------------------------------

FAILED_LOGIN_THRESHOLD = 3

SQL_INJECTION_PATTERNS = [
    r"(\bor\b|\band\b).*=",    # OR 1=1
    r"' OR '1'='1",
    r"--",
    r";",
]

SUSPICIOUS_ENDPOINTS = [
    "/admin",
    "/wp-admin",
    "/login",
    "/config",
]


# -------------------------------
# ANALYZER CLASS
# -------------------------------

class LogAnalyzer:

    def __init__(self, logfile):
        self.logfile = logfile
        self.failed_logins = defaultdict(int)
        self.sql_injections = []
        self.suspicious_access = []
        self.total_lines = 0

    def analyze(self):
        try:
            with open(self.logfile, "r") as file:
                for line in file:
                    self.total_lines += 1
                    self.check_failed_login(line)
                    self.check_sql_injection(line)
                    self.check_suspicious_endpoint(line)

        except FileNotFoundError:
            print("Log file not found.")
            sys.exit(1)

    # -------------------------------
    # Detection Methods
    # -------------------------------

    def extract_ip(self, line):
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        return match.group(1) if match else None

    def check_failed_login(self, line):
        if "Failed login" in line:
            ip = self.extract_ip(line)
            if ip:
                self.failed_logins[ip] += 1

    def check_sql_injection(self, line):
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                ip = self.extract_ip(line)
                if ip:
                    self.sql_injections.append((ip, line.strip()))

    def check_suspicious_endpoint(self, line):
        for endpoint in SUSPICIOUS_ENDPOINTS:
            if endpoint in line:
                ip = self.extract_ip(line)
                if ip:
                    self.suspicious_access.append((ip, endpoint))

    # -------------------------------
    # Reporting
    # -------------------------------

    def generate_report(self):
        report_lines = []
        report_lines.append("===== SECURITY LOG ANALYSIS REPORT =====")
        report_lines.append(f"Analysis Time: {datetime.now()}")
        report_lines.append(f"Total Log Lines Analyzed: {self.total_lines}")
        report_lines.append("")

        # Failed login summary
        report_lines.append("---- Brute Force Detection ----")
        for ip, count in self.failed_logins.items():
            if count >= FAILED_LOGIN_THRESHOLD:
                report_lines.append(f"[ALERT] {ip} - {count} failed login attempts")

        # SQL Injection summary
        report_lines.append("\n---- SQL Injection Attempts ----")
        for ip, line in self.sql_injections:
            report_lines.append(f"[ALERT] {ip} - Suspicious Query: {line}")

        # Suspicious endpoints
        report_lines.append("\n---- Suspicious Endpoint Access ----")
        for ip, endpoint in self.suspicious_access:
            report_lines.append(f"[WARNING] {ip} accessed {endpoint}")

        if len(report_lines) <= 6:
            report_lines.append("No major threats detected.")

        return "\n".join(report_lines)

    def save_report(self, content):
        with open("security_report.txt", "w") as file:
            file.write(content)


# -------------------------------
# MAIN PROGRAM
# -------------------------------

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]

    analyzer = LogAnalyzer(logfile)
    analyzer.analyze()

    report = analyzer.generate_report()
    analyzer.save_report(report)

    print(report)
    print("\nReport saved as security_report.txt")


if __name__ == "__main__":
    main()