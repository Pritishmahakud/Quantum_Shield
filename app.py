"""
Quantum_Shield v3 — Flask + SocketIO Backend
=============================================
Features:
  1. Text Encryption  — RSA, ECC, Kyber
  2. File Encryption  — Upload & download .enc files
  3. Digital Signatures — Dilithium sign/verify
  4. Benchmark        — Timing charts
  5. Secure Chat      — Real-time Kyber+AES+Dilithium encrypted chat
"""

import time, base64, os, struct, statistics, secrets, hashlib
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, join_room, emit

from crypto.rsa_algo       import rsa_keygen, rsa_encrypt, rsa_decrypt
from crypto.ecc_algo       import ecc_keygen, ecc_encrypt, ecc_decrypt
from crypto.kyber_algo     import kyber_keygen, kyber_encaps, kyber_decaps, kyber_encrypt, kyber_decrypt
from crypto.dilithium_algo import dilithium_keygen, dilithium_sign, dilithium_verify, dilithium_full_demo, dilithium_verify_tampered

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── ROOM STORAGE ─────────────────────────────────────────────────────────────
# { room_id: { users: [{sid, name}], kyber_pks: {sid: pk_hex}, dil_pks: {sid: {pk_hex, name}} } }
rooms = {}


# ── HELPERS ───────────────────────────────────────────────────────────────────
def _run_rsa(message):
    t0 = time.perf_counter()
    pub, priv, pub_size = rsa_keygen()
    ct  = rsa_encrypt(pub, message)
    dec = rsa_decrypt(priv, ct)
    ms  = round((time.perf_counter() - t0) * 1000, 2)
    return {"ciphertext_hex": ct.hex()[:80]+"…", "decrypted": dec, "time_ms": ms,
            "key_size": "2048 bits", "quantum_safe": False,
            "basis": "Integer Factorization Problem", "match": dec == message}


def _run_ecc(message):
    t0 = time.perf_counter()
    a_pub, a_priv, b_pub, b_priv, a_pub_hex = ecc_keygen()
    ct, iv, tag = ecc_encrypt(a_priv, b_pub, message)
    dec = ecc_decrypt(b_priv, a_pub, ct, iv, tag)
    ms  = round((time.perf_counter() - t0) * 1000, 2)
    return {"ciphertext_hex": ct.hex()[:80]+"…", "alice_pub_hex": a_pub_hex[:48]+"…",
            "decrypted": dec, "time_ms": ms, "key_size": "256 bits",
            "quantum_safe": False, "basis": "Elliptic Curve Discrete Log Problem", "match": dec == message}


def _run_kyber(message):
    t0 = time.perf_counter()
    pk, sk = kyber_keygen()
    ct_kem, key_s = kyber_encaps(pk)
    key_r = kyber_decaps(sk, ct_kem)
    ct_msg, iv, tag = kyber_encrypt(key_s, message)
    dec = kyber_decrypt(key_r, ct_msg, iv, tag)
    ms  = round((time.perf_counter() - t0) * 1000, 2)
    return {"ciphertext_hex": ct_msg.hex()[:80]+"…", "shared_key_hex": key_s.hex()[:48]+"…",
            "keys_match": key_s == key_r, "decrypted": dec, "time_ms": ms,
            "key_size": "800 bits (Kyber-512 PK)", "quantum_safe": True,
            "basis": "Module-LWE (Lattice)", "nist_standard": "ML-KEM (FIPS 203, 2024)", "match": dec == message}


# ── HTTP ROUTES ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# 1. TEXT ENCRYPTION
@app.route("/api/encrypt/text", methods=["POST"])
def encrypt_text():
    data = request.get_json(force=True)
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400
    try:
        results = {"rsa": _run_rsa(message), "ecc": _run_ecc(message), "kyber": _run_kyber(message)}
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"success": True, "results": results})


# 2. FILE ENCRYPTION
@app.route("/api/encrypt/file", methods=["POST"])
def encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    algorithm = request.form.get("algorithm", "kyber")
    raw = f.read()
    try:
        message = raw.decode("utf-8", errors="replace")
    except Exception:
        return jsonify({"error": "Could not read file"}), 400
    try:
        if algorithm == "rsa":
            pub, priv, _ = rsa_keygen()
            payload = rsa_encrypt(pub, message)
            ext = "rsa.enc"
        elif algorithm == "ecc":
            a_pub, a_priv, b_pub, b_priv, _ = ecc_keygen()
            ct, iv, tag = ecc_encrypt(a_priv, b_pub, message)
            payload = iv + tag + ct
            ext = "ecc.enc"
        else:
            pk, sk = kyber_keygen()
            ct_kem, key_s = kyber_encaps(pk)
            ct_msg, iv, tag = kyber_encrypt(key_s, message)
            payload = struct.pack(">H", len(pk)) + pk + struct.pack(">H", len(ct_kem)) + ct_kem + iv + tag + ct_msg
            ext = "kyber.enc"
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    original_name = os.path.splitext(f.filename)[0] if f.filename else "file"
    return jsonify({"success": True, "filename": f"{original_name}.{ext}", "algorithm": algorithm.upper(),
                    "original_size": len(raw), "encrypted_size": len(payload),
                    "b64_data": base64.b64encode(payload).decode()})


# 3. DIGITAL SIGNATURES
@app.route("/api/sign", methods=["POST"])
def sign_message():
    data = request.get_json(force=True)
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400
    try:
        result = dilithium_full_demo(message)
        pk, sk = dilithium_keygen()
        sig = dilithium_sign(sk, message)
        result["tamper_demo"] = dilithium_verify_tampered(pk, message, message + " [TAMPERED]", sig)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"success": True, "result": result})


# 4. BENCHMARK
@app.route("/api/benchmark", methods=["POST"])
def benchmark():
    data = request.get_json(force=True)
    iterations = min(int(data.get("iterations", 20)), 50)
    message = "Benchmark test message for Quantum_Shield."

    def measure(fn, n):
        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t0) * 1000)
        return {"avg": round(statistics.mean(times), 2), "min": round(min(times), 2),
                "max": round(max(times), 2),
                "stdev": round(statistics.stdev(times) if len(times) > 1 else 0, 2),
                "all": [round(t, 2) for t in times]}

    try:
        from dilithium_py.ml_dsa import ML_DSA_44
        results = {
            "rsa": measure(lambda: (lambda pub, priv, _: rsa_decrypt(priv, rsa_encrypt(pub, message)))(*rsa_keygen()), iterations),
            "ecc": measure(lambda: (lambda ap, apr, bp, bpr, _: ecc_decrypt(bpr, ap, *ecc_encrypt(apr, bp, message)))(*ecc_keygen()), iterations),
            "kyber": measure(lambda: (lambda pk, sk: kyber_decrypt(*kyber_decaps(sk, (lambda ct, k: (ct, k))(*kyber_encaps(pk))[0:1] + [kyber_decaps(sk, kyber_encaps(pk)[0])][0:0] or kyber_encaps(pk))[0], *kyber_encrypt(kyber_encaps(pk)[1], message)[0:3]))(*kyber_keygen()), iterations) if False else
                    measure(lambda: _kyber_bench(message), iterations),
            "dilithium": measure(lambda: ML_DSA_44.verify(*(lambda pk, sk: (pk, message.encode(), ML_DSA_44.sign(sk, message.encode())))(*ML_DSA_44.keygen())), iterations),
            "iterations": iterations,
            "key_sizes": {"rsa": 2048, "ecc": 256, "kyber_pk": 800, "dilithium_pk": 1312},
        }
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"success": True, "results": results})


def _kyber_bench(message):
    pk, sk = kyber_keygen()
    ct_kem, key_s = kyber_encaps(pk)
    key_r = kyber_decaps(sk, ct_kem)
    ct_msg, iv, tag = kyber_encrypt(key_s, message)
    kyber_decrypt(key_r, ct_msg, iv, tag)


# 5. CHAT CRYPTO ENDPOINTS (browser calls these, server does crypto)
@app.route("/api/chat/kyber_keygen", methods=["POST"])
def chat_kyber_keygen():
    pk, sk = kyber_keygen()
    return jsonify({"pk_hex": pk.hex(), "sk_hex": sk.hex()})


@app.route("/api/chat/kyber_encaps", methods=["POST"])
def chat_kyber_encaps():
    data = request.get_json(force=True)
    from kyber_py.ml_kem import ML_KEM_512
    pk = bytes.fromhex(data["pk_hex"])
    raw, ct = ML_KEM_512.encaps(pk)
    aes_key = hashlib.sha256(raw).digest()
    return jsonify({"ct_hex": ct.hex(), "shared_key_hex": aes_key.hex()})


@app.route("/api/chat/kyber_decaps", methods=["POST"])
def chat_kyber_decaps():
    data = request.get_json(force=True)
    from kyber_py.ml_kem import ML_KEM_512
    sk = bytes.fromhex(data["sk_hex"])
    ct = bytes.fromhex(data["ct_hex"])
    raw = ML_KEM_512.decaps(sk, ct)
    aes_key = hashlib.sha256(raw).digest()
    return jsonify({"shared_key_hex": aes_key.hex()})


@app.route("/api/chat/dil_keygen", methods=["POST"])
def chat_dil_keygen():
    from dilithium_py.ml_dsa import ML_DSA_44
    pk, sk = ML_DSA_44.keygen()
    return jsonify({"pk_hex": pk.hex(), "sk_hex": sk.hex()})


@app.route("/api/chat/encrypt_msg", methods=["POST"])
def chat_encrypt_msg():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    data = request.get_json(force=True)
    aes_key = bytes.fromhex(data["shared_key_hex"])
    iv = os.urandom(12)
    ct_with_tag = AESGCM(aes_key).encrypt(iv, data["message"].encode("utf-8"), None)
    return jsonify({"ct_hex": ct_with_tag[:-16].hex(), "iv_hex": iv.hex(), "tag_hex": ct_with_tag[-16:].hex()})


@app.route("/api/chat/decrypt_msg", methods=["POST"])
def chat_decrypt_msg():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    data = request.get_json(force=True)
    aes_key = bytes.fromhex(data["shared_key_hex"])
    ct = bytes.fromhex(data["ct_hex"])
    iv = bytes.fromhex(data["iv_hex"])
    tag = bytes.fromhex(data["tag_hex"])
    plaintext = AESGCM(aes_key).decrypt(iv, ct + tag, None)
    return jsonify({"message": plaintext.decode("utf-8")})


@app.route("/api/chat/sign_msg", methods=["POST"])
def chat_sign_msg():
    from dilithium_py.ml_dsa import ML_DSA_44
    data = request.get_json(force=True)
    sk = bytes.fromhex(data["sk_hex"])
    sig = ML_DSA_44.sign(sk, data["message"].encode("utf-8"))
    return jsonify({"sig_hex": sig.hex()})


@app.route("/api/chat/verify_msg", methods=["POST"])
def chat_verify_msg():
    from dilithium_py.ml_dsa import ML_DSA_44
    data = request.get_json(force=True)
    pk = bytes.fromhex(data["pk_hex"])
    sig = bytes.fromhex(data["sig_hex"])
    try:
        valid = ML_DSA_44.verify(pk, data["message"].encode("utf-8"), sig)
    except Exception:
        valid = False
    return jsonify({"valid": valid})


# ── SOCKETIO EVENTS ───────────────────────────────────────────────────────────

def _other_users(room_id, my_sid):
    return [u for u in rooms.get(room_id, {}).get("users", []) if u["sid"] != my_sid]


@socketio.on("create_room")
def handle_create_room(data=None):
    room_id = secrets.token_urlsafe(5).upper().replace("-", "X").replace("_", "Y")[:6]
    username = (data or {}).get("username", "Agent")
    rooms[room_id] = {"users": [], "kyber_pks": {}, "dil_pks": {}}
    join_room(room_id)  # ← THIS was missing
    rooms[room_id]["users"].append({"sid": request.sid, "name": username})
    emit("room_created", {"room_id": room_id})


@socketio.on("join_chat_room")
def handle_join(data):
    room_id = data.get("room_id", "").upper()
    username = data.get("username", "Agent")[:20]
    if room_id not in rooms:
        emit("chat_error", {"msg": "Room not found. Check the code."})
        return
    if len(rooms[room_id]["users"]) >= 2:
        emit("chat_error", {"msg": "Room is full (max 2 users)."})
        return
    join_room(room_id)
    rooms[room_id]["users"].append({"sid": request.sid, "name": username})
    user_count = len(rooms[room_id]["users"])
    emit("joined_ok", {"user_count": user_count, "room_id": room_id, "username": username})
    if user_count == 2:
        socketio.emit("partner_joined", {"msg": f"{username} has entered the channel."}, to=room_id)


@socketio.on("share_kyber_pk")
def handle_share_pk(data):
    room_id = data["room_id"]
    rooms[room_id]["kyber_pks"][request.sid] = data["pk_hex"]
    for u in _other_users(room_id, request.sid):
        emit("receive_kyber_pk", {"pk_hex": data["pk_hex"]}, to=u["sid"])


@socketio.on("share_kyber_ct")
def handle_share_ct(data):
    room_id = data["room_id"]
    for u in _other_users(room_id, request.sid):
        emit("receive_kyber_ct", {"ct_hex": data["ct_hex"]}, to=u["sid"])


@socketio.on("share_dil_pk")
def handle_share_dil_pk(data):
    room_id = data["room_id"]
    rooms[room_id]["dil_pks"][request.sid] = data["pk_hex"]
    for u in _other_users(room_id, request.sid):
        emit("receive_dil_pk", {"pk_hex": data["pk_hex"], "username": data.get("username", "User")}, to=u["sid"])


@socketio.on("key_exchange_done")
def handle_kex_done(data):
    room_id = data["room_id"]
    for u in _other_users(room_id, request.sid):
        emit("partner_key_ready", {}, to=u["sid"])


@socketio.on("chat_message")
def handle_chat_message(data):
    room_id = data["room_id"]
    for u in _other_users(room_id, request.sid):
        emit("receive_message", {
            "ct_hex":    data["ct_hex"],
            "iv_hex":    data["iv_hex"],
            "tag_hex":   data["tag_hex"],
            "sig_hex":   data["sig_hex"],
            "username":  data.get("username", "User"),
            "timestamp": data.get("timestamp", ""),
        }, to=u["sid"])


@socketio.on("disconnect")
def handle_disconnect():
    for room_id, room in list(rooms.items()):
        was_here = any(u["sid"] == request.sid for u in room["users"])
        room["users"] = [u for u in room["users"] if u["sid"] != request.sid]
        room["kyber_pks"].pop(request.sid, None)
        room["dil_pks"].pop(request.sid, None)
        if was_here and room["users"]:
            socketio.emit("partner_left", {"msg": "Partner disconnected. Channel closed."}, to=room_id)


if __name__ == "__main__":
    print("\n  ┌─────────────────────────────────────────┐")
    print("  │   QUANTUM_SHIELD  ·  v3                 │")
    print("  │   Open → http://localhost:5000           │")
    print("  └─────────────────────────────────────────┘\n")
    socketio.run(app, host='0.0.0.0', debug=True, port=5000)
