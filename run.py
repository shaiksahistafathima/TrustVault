from app import create_app
from seed import seed_database

app = create_app()

if __name__ == "__main__":
    seed_database()
    print("\n" + "=" * 60)
    print("  🔒 TRUSTVAULT — SECURE DOCUMENT REPOSITORY RUNNING")
    print("  Host: http://127.0.0.1:5000")
    print("  Seed Accounts:")
    print("   - Admin:   admin@trustvault.local   (PW: AdminSecure2026!)")
    print("   - Owner:   owner@trustvault.local   (PW: OwnerSecure2026!)")
    print("   - Viewer:  viewer@trustvault.local  (PW: ViewerSecure2026!)")
    print("   - Outsider:outsider@trustvault.local(PW: OutsiderSecure2026!)")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
