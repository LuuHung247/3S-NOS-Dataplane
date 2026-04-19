# check_sonic.py
import pexpect, time, sys

NODES = [
    (5002, "SPINE"),
    (5005, "LEAF-1"),
    (5017, "LEAF-2"),
]

def check_node(port, name):
    print(f"[{name}] Connecting to port {port}...")
    try:
        c = pexpect.spawn(f"telnet 127.0.0.1 {port}", timeout=30)
        c.expect("Connected")
        print(f"[{name}] TCP OK")

        c.sendline("")
        time.sleep(1)
        c.sendline("")

        idx = c.expect(["admin@sonic", "login:", pexpect.TIMEOUT], timeout=20)

        if idx == 2:
            print(f"[{name}] Still booting (timeout)")
            return False

        if idx == 1:
            print(f"[{name}] At login prompt, authenticating...")
            c.sendline("admin")
            c.expect("Password:")
            c.sendline("YourPaSsWoRd")
            c.expect("admin@sonic", timeout=20)

        print(f"[{name}] ✅ READY")
        c.close()
        return True

    except pexpect.exceptions.EOF:
        print(f"[{name}] ❌ Connection refused (EOF)")
    except Exception as e:
        print(f"[{name}] ❌ Error: {e}")
    return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    for port, name in NODES:
        if target in ("all", name):
            check_node(port, name)
            print("---")