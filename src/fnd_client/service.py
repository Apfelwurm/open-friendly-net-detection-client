#!/usr/bin/env python3
import os
import signal
import socket
import threading
import time
import yaml
import logging
import base64
import secrets
import selectors
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import struct
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONFIG_PATH = '/etc/fnd-client/config.yaml'
RUN_DIR = '/run/fnd'
STATE_FILE = os.path.join(RUN_DIR, 'network_id')
SOCKET_PATH = os.path.join(RUN_DIR, 'socket')
DHCP_IP_FILE = os.path.join(RUN_DIR, 'dhcp_server_ip')
NONCE_VALID_SECS = 30
UDP_SERVER_PORT = 32125
TCP_MAX_CERT_LEN = 4096
MAGIC = b'FND1'

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger('fnd-client')

@dataclass
class NetworkConfig:
    pubkey: str
    fallback_servers: List[str] = field(default_factory=list)

@dataclass
class Config:
    poll_interval_seconds: int = 900
    react_to_netlink: bool = True
    handshake_timeout_seconds: int = 10
    custom_dhcp_option: int = 224
    networks: Dict[str, NetworkConfig] = field(default_factory=dict)

_current_config: Config = Config()
_current_network_id: str = 'unknown'
_config_mtime: float = 0.0
_stop_event = threading.Event()
_nonce_store: Dict[bytes, float] = {}
_config_lock = threading.Lock()
_state_lock = threading.Lock()
selector = selectors.DefaultSelector()


def load_config():
    global _current_config, _config_mtime
    try:
        st = os.stat(CONFIG_PATH)
        if st.st_mtime == _config_mtime:
            return
        with open(CONFIG_PATH, 'r') as f:
            raw = yaml.safe_load(f) or {}
        networks = {}
        for name, ncfg in (raw.get('networks') or {}).items():
            networks[name] = NetworkConfig(pubkey=ncfg['pubkey'], fallback_servers=ncfg.get('fallback_servers', []))
        _current_config = Config(
            poll_interval_seconds=raw.get('poll_interval_seconds', 900),
            react_to_netlink=raw.get('react_to_netlink', True),
            handshake_timeout_seconds=raw.get('handshake_timeout_seconds', 10),
            custom_dhcp_option=raw.get('custom_dhcp_option', 224),
            networks=networks
        )
        _config_mtime = st.st_mtime
        logger.info('Config reloaded')
    except FileNotFoundError:
        logger.warning('Config file missing %s', CONFIG_PATH)
    except Exception:
        logger.exception('Failed to load config')


def publish_state():
    with _state_lock:
        tmp = STATE_FILE + '.new'
        os.makedirs(RUN_DIR, exist_ok=True)
        with open(tmp, 'w') as f:
            f.write(_current_network_id + '\n')
        os.replace(tmp, STATE_FILE)


def set_network_id(nid: str):
    global _current_network_id
    with _state_lock:
        if nid != _current_network_id:
            _current_network_id = nid
            logger.info('Network ID -> %s', nid)
            publish_state()


def build_server_candidates() -> List[str]:
    ips: List[str] = []
    try:
        with open(DHCP_IP_FILE, 'r') as f:
            ip = f.read().strip()
            if ip:
                ips.append(ip)
    except FileNotFoundError:
        pass
    with _config_lock:
        for net in _current_config.networks.values():
            for ip in net.fallback_servers:
                if ip not in ips:
                    ips.append(ip)
    return ips


def gen_nonce() -> bytes:
    nonce = secrets.token_bytes(32)
    _nonce_store[nonce] = time.time()
    now = time.time()
    for n, ts in _nonce_store.copy().items():  # remove stale
        if now - ts > NONCE_VALID_SECS:
            _nonce_store.pop(n, None)
    return nonce


def verify_server_key(pubkey_bytes: bytes) -> Optional[str]:
    pk_b64 = base64.b64encode(pubkey_bytes).decode('ascii')
    with _config_lock:
        for name, net in _current_config.networks.items():
            if pk_b64 == net.pubkey:
                return name
    return None

# Helpers for reverse handshake

def _recv_exact(sock: socket.socket, length: int) -> Optional[bytes]:
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def _receive_certificate(conn: socket.socket) -> Optional[bytes]:
    hdr = _recv_exact(conn, 2)
    if not hdr:
        return None
    (cert_len,) = struct.unpack('!H', hdr)
    if cert_len <= 0 or cert_len > TCP_MAX_CERT_LEN:
        return None
    return _recv_exact(conn, cert_len)


def perform_reverse_handshake(candidate_ip: str) -> Optional[str]:
    try:
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(('', 0))
        lsock.listen(1)
        lsock_port = lsock.getsockname()[1]
        lsock.settimeout(_current_config.handshake_timeout_seconds)
        nonce = gen_nonce()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(_current_config.handshake_timeout_seconds)
        probe = MAGIC + struct.pack('!H', lsock_port) + nonce
        udp.sendto(probe, (candidate_ip, UDP_SERVER_PORT))
        udp.close()
        conn, addr = lsock.accept()
        with conn:
            conn.settimeout(_current_config.handshake_timeout_seconds)
            if _recv_exact(conn, len(MAGIC)) != MAGIC:
                return None
            cert_bytes = _receive_certificate(conn)
            if not cert_bytes:
                return None
            sig = _recv_exact(conn, 64)
            if not sig:
                return None
            try:
                cert = x509.load_der_x509_certificate(cert_bytes)
                pubkey = cert.public_key()
            except Exception:
                return None
            if not isinstance(pubkey, Ed25519PublicKey):
                return None
            pub_bytes = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            try:
                pubkey.verify(sig, nonce)
            except Exception:
                return None
            netname = verify_server_key(pub_bytes)
            if not netname:
                logger.info('Unknown server key from %s', candidate_ip)
                return None
            conn.sendall(hashlib.sha256(pub_bytes + nonce).digest())
            return netname
    except socket.timeout:
        return None
    except Exception as e:
        logger.debug('Reverse handshake error %s: %s', candidate_ip, e)
        return None
    finally:
        try:
            lsock.close()
        except Exception:
            pass


def attempt_detection():
    load_config()
    candidates = build_server_candidates()
    for ip in candidates:
        nid = perform_reverse_handshake(ip)
        if nid:
            set_network_id(nid)
            return
    set_network_id('unknown')


def netlink_thread():
    # Minimal netlink listener for RTMGRP_LINK | RTMGRP_IPV4_IFADDR
    import socket as pysocket
    RTMGRP_LINK = 1
    RTMGRP_IPV4_IFADDR = 0x10
    nl = pysocket.socket(pysocket.AF_NETLINK, pysocket.SOCK_RAW, pysocket.NETLINK_ROUTE)
    nl.bind((0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR))
    while not _stop_event.is_set():
        try:
            data = nl.recv(65535)
            if not data:
                continue
            attempt_detection()
        except Exception:
            time.sleep(1)
    nl.close()


def periodic_thread():
    while not _stop_event.is_set():
        with _config_lock:
            interval = _current_config.poll_interval_seconds
        attempt_detection()
        _stop_event.wait(interval)


def socket_server_thread():
    # Provide result; use 0666 perms so clients can connect (UNIX sockets need write). Read-only semantic enforced by protocol.
    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    srv.listen(5)
    while not _stop_event.is_set():
        try:
            conn, _ = srv.accept()
            with _state_lock:
                nid = _current_network_id
            try:
                conn.sendall(nid.encode('utf-8') + b'\n')
            finally:
                conn.close()
        except Exception:
            time.sleep(0.2)
    srv.close()


def handle_signal(signum, frame):
    if signum in (signal.SIGINT, signal.SIGTERM):
        _stop_event.set()
    elif signum == signal.SIGUSR1:
        attempt_detection()


def main():
    load_config()
    publish_state()
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGUSR1, handle_signal)
    threads = [
        threading.Thread(target=socket_server_thread, daemon=True),
        threading.Thread(target=periodic_thread, daemon=True)
    ]
    with _config_lock:
        if _current_config.react_to_netlink:
            threads.append(threading.Thread(target=netlink_thread, daemon=True))
    for t in threads:
        t.start()
    attempt_detection()
    try:
        while not _stop_event.is_set():
            time.sleep(1)
    finally:
        _stop_event.set()
        for t in threads:
            t.join(timeout=2)

if __name__ == '__main__':
    main()
