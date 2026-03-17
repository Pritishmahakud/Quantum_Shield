"""Quantum_Shield v3 — Launcher"""
import subprocess, sys

print("""
  ╔══════════════════════════════════════════════╗
  ║  QUANTUM_SHIELD  v3  //  POST-QUANTUM CRYPTO  ║
  ╚══════════════════════════════════════════════╝
""")
print("  [1]  Terminal Demo (main.py)")
print("  [2]  Web App at http://localhost:5000")
print("  [q]  Quit\n")

c = input("  > ").strip().lower()
if c in ('1','terminal'):
    subprocess.run([sys.executable, 'main.py'])
elif c in ('2','web'):
    print("\n  🌐 http://localhost:5000\n")
    subprocess.run([sys.executable, 'app.py'])
else:
    print("  Goodbye.")
