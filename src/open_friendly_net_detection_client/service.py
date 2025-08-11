#!/usr/bin/env python3
"""Friendly Network Detection (FND) client service.

High-level flow:
  * Loads configuration describing trusted networks and their server Ed25519 public keys.
  * Exposes the currently detected network id via a UNIX domain socket and a state file.
  * Discovers candidate server IPs from a custom DHCP option plus configured fallback lists.
  * On triggers (startup, periodic timer, netlink interface/address change, or SIGUSR1) it
    performs a reverse handshake with each candidate until one succeeds:
       - Create ephemeral TCP listener
       - Generate nonce; send UDP probe (MAGIC + listener port + nonce) to server port 32125
       - Server connects back; sends MAGIC, DER Ed25519 certificate, signature over nonce
       - Client validates signature & pinned public key; replies with hash(pubkey||nonce)
       - Maps pubkey to network id and publishes result
  * If no server validates, network id reverts to 'unknown'.

Security decisions:
  * Only server authenticity (no client auth) – acceptable for identifying friendly network.
  * Ed25519 public key pinning (base64) in config; certificate acts only as key container.
  * 32‑byte nonces with short lifetime defend against replay of prior signatures.
"""
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
try:  # Python >=3.8
    from importlib.metadata import version as _pkg_version, distributions as _pkg_distributions
except Exception:  # pragma: no cover
    _pkg_version = None
    _pkg_distributions = lambda: []  # type: ignore

CONFIG_PATH = '/etc/open-friendly-net-detection-client/config.yaml'
RUN_DIR = '/run/fnd'
STATE_FILE = os.path.join(RUN_DIR, 'network_id')
SOCKET_PATH = os.path.join(RUN_DIR, 'socket')
DHCP_IP_FILE = os.path.join(RUN_DIR, 'dhcp_server_ip')
NONCE_VALID_SECS = 30
UDP_SERVER_PORT = 32125
TCP_MAX_CERT_LEN = 4096
MAGIC = b'FND1'

# Initial basic config; will be refined after loading user config (log level etc.)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger('open-friendly-net-detection-client')

@dataclass
class NetworkConfig:
    pubkey: str  # Base64-encoded raw Ed25519 public key
    fallback_servers: List[str] = field(default_factory=list)  # Static IPs if DHCP option absent

@dataclass
class Config:
    poll_interval_seconds: int = 900
    react_to_netlink: bool = True
    handshake_timeout_seconds: int = 10
    custom_dhcp_option: int = 224
    log_level: str = 'INFO'
    networks: Dict[str, NetworkConfig] = field(default_factory=dict)

_current_config: Config = Config()
_current_network_id: str = 'unknown'
_config_mtime: float = 0.0  # Last loaded mtime to support on-the-fly reloads
_stop_event = threading.Event()
_nonce_store: Dict[bytes, float] = {}  # nonce -> creation timestamp
_config_lock = threading.Lock()
_state_lock = threading.Lock()
# Subscribers (streaming socket clients) tracking
_subscribers: List[socket.socket] = []
_subscribers_lock = threading.Lock()
selector = selectors.DefaultSelector()

# ---------------------------------------------------------------------------
# Helpers / utilities
# ---------------------------------------------------------------------------

def get_running_version() -> str:
    """Best-effort package version lookup for startup log.

    Added debugging: when log level is DEBUG or env FND_DEBUG_LIST_PACKAGES=1,
    enumerate visible installed distributions to aid diagnosing why version
    metadata may not be available in production deployments.
    """
    if _pkg_version is None:
        return 'unknown'
    # Conditional enumeration
    if os.environ.get('FND_DEBUG_LIST_PACKAGES') == '1' or logger.isEnabledFor(logging.DEBUG):
        try:
            names: List[str] = []
            for dist in _pkg_distributions():  # type: ignore
                try:
                    meta = dist.metadata  # type: ignore[attr-defined]
                    name = (meta.get('Name') or meta.get('name') or '').strip()
                except Exception:
                    name = ''
                if name:
                    names.append(name)
            unique = sorted(set(names), key=str.lower)
            logger.debug('Visible installed distributions (%d): %s', len(unique), ', '.join(unique))
        except Exception as e:  # pragma: no cover
            logger.debug('Failed to enumerate distributions: %s', e)
    try:
        return _pkg_version('open-friendly-net-detection-client')
    except Exception as e:  # pragma: no cover
        logger.debug('Version lookup failed: %s', e)
        return 'unknown'


def load_config():
    """Load (or reload) YAML configuration if it changed on disk."""
    global _current_config, _config_mtime
    try:
        st = os.stat(CONFIG_PATH)
        if st.st_mtime == _config_mtime:
            return  # unchanged
        logger.debug('Detected config mtime change; reloading %s', CONFIG_PATH)
        with open(CONFIG_PATH, 'r') as f:
            raw = yaml.safe_load(f) or {}
        networks = {}
        for name, ncfg in (raw.get('networks') or {}).items():
            try:
                networks[name] = NetworkConfig(pubkey=ncfg['pubkey'], fallback_servers=ncfg.get('fallback_servers', []))
            except KeyError:
                logger.warning('Skipping network %s due to missing keys', name)
        _current_config = Config(
            poll_interval_seconds=raw.get('poll_interval_seconds', 900),
            react_to_netlink=raw.get('react_to_netlink', True),
            handshake_timeout_seconds=raw.get('handshake_timeout_seconds', 10),
            custom_dhcp_option=raw.get('custom_dhcp_option', 224),
            log_level=raw.get('log_level', raw.get('logging', {}).get('level', 'INFO')),
            networks=networks
        )
        # Apply log level
        level_name = _current_config.log_level.upper()
        level = getattr(logging, level_name, logging.INFO)
        logger.setLevel(level)
        logger.info('Config reloaded (networks=%d, poll=%ss, timeout=%ss, log_level=%s)',
                    len(_current_config.networks), _current_config.poll_interval_seconds,
                    _current_config.handshake_timeout_seconds, level_name)
        _config_mtime = st.st_mtime
    except FileNotFoundError:
        logger.warning('Config file missing %s', CONFIG_PATH)
    except Exception:
        logger.exception('Failed to load config')


def publish_state():
    """Atomically write current network id to state file for simple consumers.

    NOTE: Caller must NOT already hold _state_lock (to avoid deadlock).
    """
    with _state_lock:
        tmp = STATE_FILE + '.new'
        os.makedirs(RUN_DIR, exist_ok=True)
        with open(tmp, 'w') as f:
            f.write(_current_network_id + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
        logger.debug('State file updated -> %s (%s)', _current_network_id, STATE_FILE)


def _broadcast_network_id():
    """Send current network id (newline terminated) to all streaming subscribers."""
    line = (_current_network_id + '\n').encode('utf-8')
    to_remove: List[socket.socket] = []
    with _subscribers_lock:
        for conn in list(_subscribers):
            try:
                conn.sendall(line)
            except Exception as e:
                logger.debug('Dropping subscriber (send error: %s)', e)
                to_remove.append(conn)
        for conn in to_remove:
            try:
                _subscribers.remove(conn)
                conn.close()
            except Exception:
                pass
    if to_remove:
        logger.debug('Removed %d dead subscribers; active=%d', len(to_remove), len(_subscribers))


def set_network_id(nid: str):
    """Update and publish network id if changed (fixed deadlock in previous version)."""
    global _current_network_id
    changed = False
    with _state_lock:
        if nid != _current_network_id:
            logger.info('Network ID change: %s -> %s', _current_network_id, nid)
            _current_network_id = nid
            changed = True
    if changed:
        publish_state()
        _broadcast_network_id()  # push update to streaming clients
    else:
        logger.debug('Network ID unchanged (%s)', _current_network_id)


def build_server_candidates() -> List[str]:
    """Return ordered list of candidate server IPs (DHCP-discovered first)."""
    ips: List[str] = []
    dhcp_ip = None
    try:
        with open(DHCP_IP_FILE, 'r') as f:
            dhcp_ip = f.read().strip() or None
            if dhcp_ip:
                ips.append(dhcp_ip)
    except FileNotFoundError:
        logger.debug('No DHCP-provided server IP file (%s) yet', DHCP_IP_FILE)
    if dhcp_ip:
        logger.debug('DHCP provided server IP: %s', dhcp_ip)
    # 2. All unique fallback IPs from config
    with _config_lock:
        for netname, net in _current_config.networks.items():
            for ip in net.fallback_servers:
                if ip not in ips:
                    ips.append(ip)
                    logger.debug('Added fallback IP %s (network %s)', ip, netname)
    logger.debug('Built candidate server list: %s', ips)
    return ips


def gen_nonce() -> bytes:
    """Generate a fresh nonce and prune stale ones."""
    nonce = secrets.token_bytes(32)
    _nonce_store[nonce] = time.time()
    now = time.time()
    for n, ts in list(_nonce_store.items()):
        if now - ts > NONCE_VALID_SECS:
            _nonce_store.pop(n, None)
    return nonce


def verify_server_key(pubkey_bytes: bytes) -> Optional[str]:
    """Map a raw Ed25519 pubkey to configured network name if pinned."""
    pk_b64 = base64.b64encode(pubkey_bytes).decode('ascii')
    with _config_lock:
        for name, net in _current_config.networks.items():
            if pk_b64 == net.pubkey:
                return name
    return None

# Helpers for reverse handshake

def _recv_exact(sock: socket.socket, length: int) -> Optional[bytes]:
    """Read exactly length bytes or return None if EOF/short."""
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _receive_certificate(conn: socket.socket) -> Optional[bytes]:
    """Receive length-prefixed (2B) DER certificate bytes with bounds checks."""
    hdr = _recv_exact(conn, 2)
    if not hdr:
        return None
    (cert_len,) = struct.unpack('!H', hdr)
    if cert_len <= 0 or cert_len > TCP_MAX_CERT_LEN:
        return None
    return _recv_exact(conn, cert_len)


def perform_reverse_handshake(candidate_ip: str) -> Optional[str]:
    """Execute reverse handshake with a single server IP.

    Steps:
      1. Open ephemeral TCP listener
      2. Generate nonce and UDP probe (MAGIC + port + nonce) to server
      3. Accept incoming TCP, validate MAGIC
      4. Receive DER Ed25519 certificate + signature over nonce
      5. Verify signature & configured key; reply with SHA256(pubkey||nonce)
    Returns network id string on success else None.
    """
    logger.debug('Starting reverse handshake with %s', candidate_ip)
    start_time = time.time()
    try:
        # Ephemeral listening socket for server callback
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(('', 0))
        lsock.listen(1)
        lsock_port = lsock.getsockname()[1]
        lsock.settimeout(_current_config.handshake_timeout_seconds)
        nonce = gen_nonce()
        logger.debug('Listening on ephemeral TCP port %d (nonce %s)', lsock_port, nonce.hex()[:16])
        # Send UDP probe announcing where to connect back
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(_current_config.handshake_timeout_seconds)
        probe = MAGIC + struct.pack('!H', lsock_port) + nonce
        udp.sendto(probe, (candidate_ip, UDP_SERVER_PORT))
        logger.debug('Sent UDP probe to %s:%d', candidate_ip, UDP_SERVER_PORT)
        udp.close()
        # Await server connection
        conn, addr = lsock.accept()
        logger.debug('Accepted TCP callback from %s:%d', addr[0], addr[1])
        with conn:
            conn.settimeout(_current_config.handshake_timeout_seconds)
            if _recv_exact(conn, len(MAGIC)) != MAGIC:
                logger.debug('Magic mismatch from %s', candidate_ip)
                return None
            cert_bytes = _receive_certificate(conn)
            if not cert_bytes:
                logger.debug('Failed to receive certificate from %s', candidate_ip)
                return None
            sig = _recv_exact(conn, 64)  # Ed25519 signature size
            if not sig:
                logger.debug('Failed to receive signature from %s', candidate_ip)
                return None
            try:
                cert = x509.load_der_x509_certificate(cert_bytes)
                pubkey = cert.public_key()
            except Exception:
                logger.debug('Certificate parsing error from %s', candidate_ip)
                return None
            if not isinstance(pubkey, Ed25519PublicKey):  # enforce key type
                logger.debug('Non-Ed25519 key from %s', candidate_ip)
                return None
            pub_bytes = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            try:
                pubkey.verify(sig, nonce)
            except Exception:
                logger.debug('Signature verification failed from %s', candidate_ip)
                return None
            netname = verify_server_key(pub_bytes)
            if not netname:
                logger.info('Unknown server key from %s', candidate_ip)
                return None
            # Final acknowledgment (allows server to ensure freshness if desired)
            conn.sendall(hashlib.sha256(pub_bytes + nonce).digest())
            logger.info('Reverse handshake success with %s (network %s) (%.2fs)', candidate_ip, netname, time.time()-start_time)
            return netname
    except socket.timeout:
        logger.debug('Handshake timeout with %s (%.2fs)', candidate_ip, time.time()-start_time)
        return None
    except Exception as e:
        logger.debug('Reverse handshake error %s: %s (%.2fs)', candidate_ip, e, time.time()-start_time)
        return None
    finally:
        try:
            lsock.close()
        except Exception:
            pass


def attempt_detection():
    """Try all server candidates; set network id on first success else 'unknown'."""
    logger.info('Detection cycle start')
    load_config()
    candidates = build_server_candidates()
    logger.debug('Candidate list (count=%d): %s', len(candidates), candidates)
    if not candidates:
        logger.warning('No server candidates available; setting unknown')
        set_network_id('unknown')
        logger.info('Detection cycle end (no candidates)')
        return
    for ip in candidates:
        logger.info('Attempting handshake with %s', ip)
        nid = perform_reverse_handshake(ip)
        if nid:
            set_network_id(nid)
            logger.info('Detection cycle end (matched %s)', nid)
            return
    logger.info('All handshake attempts failed; network unknown')
    set_network_id('unknown')
    logger.info('Detection cycle end (no match)')


def netlink_thread():
    """Background thread: listens for link / IPv4 address changes via netlink."""
    try:
        import socket as pysocket
        RTMGRP_LINK = 1
        RTMGRP_IPV4_IFADDR = 0x10
        nl = pysocket.socket(pysocket.AF_NETLINK, pysocket.SOCK_RAW, pysocket.NETLINK_ROUTE)
        nl.bind((0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR))
        logger.info('Netlink monitor thread started')
        while not _stop_event.is_set():
            try:
                nl.settimeout(1.0)  # Add timeout to allow clean shutdown
                data = nl.recv(65535)
                if not data:
                    continue
                logger.debug('Netlink event (%d bytes)', len(data))
                attempt_detection()
            except socket.timeout:
                continue  # Normal timeout, check _stop_event
            except Exception as e:
                if not _stop_event.is_set():
                    logger.warning('Netlink error: %s; retrying in 5s', e)
                    time.sleep(5)
        nl.close()
        logger.debug('Netlink monitor thread exiting')
    except Exception as e:
        logger.error('Failed to start netlink monitoring: %s', e)
        logger.info('Falling back to periodic-only monitoring')
        # Continue running but without netlink monitoring


def periodic_thread():
    """Periodic trigger loop honoring configured poll interval."""
    logger.info('Periodic thread started')
    cycle = 0
    while not _stop_event.is_set():
        with _config_lock:
            interval = _current_config.poll_interval_seconds
        cycle += 1
        logger.info('Periodic cycle #%d (interval=%ss)', cycle, interval)
        try:
            attempt_detection()
            logger.info('Periodic cycle #%d complete; sleeping %ss', cycle, interval)
        except Exception as e:
            logger.exception('Periodic cycle #%d encountered error: %s', cycle, e)
        if _stop_event.wait(interval):
            break
    logger.info('Periodic thread exiting')


def socket_server_thread():
    """Streaming UNIX domain socket: initial id then pushes on changes.

    Protocol: Each client receives the current network id line immediately on
    connect, and again each time it changes. Lines are UTF-8 with trailing \n.
    """
    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass
    os.makedirs(RUN_DIR, exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    srv.listen(20)
    srv.settimeout(1.0)
    logger.info('Streaming socket server listening at %s', SOCKET_PATH)

    while not _stop_event.is_set():
        try:
            conn, _ = srv.accept()
            try:
                conn.settimeout(10.0)
                # Add to subscriber list
                with _subscribers_lock:
                    _subscribers.append(conn)
                    logger.debug('Subscriber added (total=%d)', len(_subscribers))
                # Immediately send current id
                with _state_lock:
                    current = _current_network_id
                try:
                    conn.sendall((current + '\n').encode('utf-8'))
                except Exception as e:
                    logger.debug('Immediate send failed, dropping subscriber: %s', e)
                    with _subscribers_lock:
                        if conn in _subscribers:
                            _subscribers.remove(conn)
                    conn.close()
            except Exception as e:
                logger.debug('Error during new subscriber handling: %s', e)
                try:
                    conn.close()
                except Exception:
                    pass
        except socket.timeout:
            continue
        except Exception as e:
            if not _stop_event.is_set():
                logger.debug('Socket server accept error: %s', e)
                time.sleep(0.2)

    # Shutdown: close all subscribers
    with _subscribers_lock:
        for conn in _subscribers:
            try:
                conn.close()
            except Exception:
                pass
        _subscribers.clear()
    try:
        srv.close()
        os.remove(SOCKET_PATH)
    except Exception:
        pass
    logger.debug('Socket server thread exiting')


def handle_signal(signum, frame):  # noqa: ARG001 (frame unused)
    """Handle termination (SIGINT/SIGTERM) and manual retrigger (SIGUSR1)."""
    if signum in (signal.SIGINT, signal.SIGTERM):
        logger.info('Received termination signal (%s); shutting down', signum)
        _stop_event.set()
    elif signum == signal.SIGUSR1:
        logger.info('Received SIGUSR1: manual detection trigger')
        attempt_detection()


def main():
    """Entry point: start threads, perform initial detection, then idle."""
    ver = get_running_version()
    logger.info('FND client starting (pid=%d, version=%s)', os.getpid(), ver)
    load_config()
    publish_state()
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGUSR1, handle_signal)
    threads = [
        threading.Thread(target=socket_server_thread, daemon=True, name='socket-server'),
        threading.Thread(target=periodic_thread, daemon=True, name='periodic')
    ]
    with _config_lock:
        if _current_config.react_to_netlink:
            threads.append(threading.Thread(target=netlink_thread, daemon=True, name='netlink'))
    for t in threads:
        t.start()
        logger.info('Started thread: %s (alive=%s)', t.name, t.is_alive())
    logger.info('Performing initial detection')
    attempt_detection()
    logger.info('Initial detection complete; entering main loop')
    try:
        while not _stop_event.is_set():
            time.sleep(5)
            for t in threads:
                if not t.is_alive():
                    logger.error('Thread %s unexpectedly stopped; marking for shutdown', t.name)
                    _stop_event.set()
    finally:
        _stop_event.set()
        logger.info('Shutting down threads')
        for t in threads:
            t.join(timeout=3)
            if t.is_alive():
                logger.warning('Thread %s did not terminate cleanly', t.name)
        logger.info('Exit complete')

if __name__ == '__main__':
    main()
