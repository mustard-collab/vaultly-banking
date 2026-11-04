# app.py
"""
VAULTLY — Digital Banking Server (v2.0 Enterprise)
Includes Persistent Storage, Admin Audit CSV/JSON Export, 
Date-Range E-Statements & Dynamic Visa/Mastercard Virtual Cards.
"""

import io
import csv
import json
import socket
from flask import Flask, request, jsonify, render_template, send_file

from banking_service import BankingService, PAKISTAN_BANKS, UTILITY_COMPANIES
import config

app = Flask(__name__)
app.secret_key = "vaultly-secure-secret-token"

# Initialize Core Banking Engine
bank = BankingService()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


@app.route("/")
def index():
    return render_template(
        "user_dashboard.html",
        bank_name=config.BANK_NAME,
        banks=PAKISTAN_BANKS,
        utilities=UTILITY_COMPANIES
    )


@app.route("/admin")
def admin():
    return render_template("admin_dashboard.html", bank_name=config.BANK_NAME)


# ==========================================
# AUTHENTICATION & ONBOARDING
# ==========================================

@app.route("/api/register/initiate", methods=["POST"])
def api_register_init():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    deposit = data.get("initial_deposit", 50000.0)
    card_scheme = data.get("card_scheme", "VISA")

    if not all([name, email, password]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    success, msg = bank.initiate_registration(name, email, password, deposit, card_scheme)
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": msg}), status_code


@app.route("/api/register/verify-otp", methods=["POST"])
def api_register_verify():
    data = request.get_json() or {}
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"success": False, "message": "Email and OTP are required."}), 400

    success, user, msg = bank.finalize_registration(email, otp)
    if success and user:
        return jsonify({
            "success": True,
            "message": msg,
            "user": {
                "name": user["name"],
                "email": user["email"],
                "account_no": user["account_no"],
                "balance": user["balance"],
                "is_frozen": user["is_frozen"],
                "card": user.get("card")
            }
        })
    return jsonify({"success": False, "message": msg}), 400


@app.route("/api/login/initiate", methods=["POST"])
def api_login_init():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    success, msg = bank.initiate_login(email, password)
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": msg}), status_code


@app.route("/api/login/verify-otp", methods=["POST"])
def api_login_verify():
    data = request.get_json() or {}
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"success": False, "message": "Email and OTP code are required."}), 400

    success, user, msg = bank.verify_login_otp(email, otp)
    if success and user:
        return jsonify({
            "success": True,
            "message": msg,
            "user": {
                "name": user["name"],
                "email": user["email"],
                "account_no": user["account_no"],
                "balance": user["balance"],
                "is_frozen": user["is_frozen"],
                "card": user.get("card")
            }
        })
    return jsonify({"success": False, "message": msg}), 400


# ==========================================
# BANKING OPERATIONS & REAL-TIME SYNC
# ==========================================

@app.route("/api/user/<account_no>", methods=["GET"])
def api_get_user(account_no):
    email = bank.acc_to_email.get(account_no)
    if not email:
        return jsonify({"success": False, "message": "Account not found."}), 404
    user = bank.users_table.get(email)
    history = bank.get_account_history(account_no, limit=25)
    return jsonify({
        "success": True,
        "user": {
            "name": user["name"],
            "email": user["email"],
            "account_no": user["account_no"],
            "balance": user["balance"],
            "is_frozen": user["is_frozen"],
            "card": user.get("card")
        },
        "transactions": history
    })


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    data = request.get_json() or {}
    sender_acc = data.get("sender_acc")
    target_bank = data.get("bank_name", "VAULTLY (Same Bank - Free)")
    receiver_acc = data.get("receiver_acc")
    amount = data.get("amount")

    if not sender_acc or not receiver_acc or not amount:
        return jsonify({"success": False, "message": "All transfer fields are required."}), 400

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid numeric transfer amount."}), 400

    success, msg, receipt = bank.execute_transfer(sender_acc, target_bank, receiver_acc, amount)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": msg,
        "receipt": receipt
    }), status_code


@app.route("/api/bill/pay", methods=["POST"])
def api_pay_bill():
    data = request.get_json() or {}
    account_no = data.get("account_no")
    company = data.get("company")
    consumer_no = data.get("consumer_no")
    amount = data.get("amount")

    if not all([account_no, company, consumer_no, amount]):
        return jsonify({"success": False, "message": "All bill fields are mandatory."}), 400

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid bill amount."}), 400

    success, msg, receipt = bank.pay_utility_bill(account_no, company, consumer_no, amount)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": msg,
        "receipt": receipt
    }), status_code


@app.route("/api/card/update", methods=["POST"])
def api_update_card():
    data = request.get_json() or {}
    account_no = data.get("account_no")
    is_active = data.get("is_active")
    intl_allowed = data.get("intl_allowed")
    online_limit = data.get("online_limit")
    scheme = data.get("scheme")

    success = bank.update_card_settings(account_no, is_active, intl_allowed, online_limit, scheme)
    return jsonify({"success": success})


@app.route("/api/statement/request", methods=["POST"])
def api_request_statement():
    data = request.get_json() or {}
    account_no = data.get("account_no")
    start_date = data.get("start_date")
    end_date = data.get("end_date")

    if not account_no:
        return jsonify({"success": False, "message": "Account number is required."}), 400

    success, msg = bank.request_and_send_statement(account_no, start_date, end_date)
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": msg}), status_code


# ==========================================
# ADMIN APIS & DATA EXPORT
# ==========================================

@app.route("/api/admin/feed", methods=["GET"])
def api_admin_feed():
    feed = bank.get_admin_audit_feed()
    all_users = bank.get_all_accounts()
    safe_users = [
        {
            "name": u["name"],
            "email": u["email"],
            "account_no": u["account_no"],
            "balance": u["balance"],
            "is_frozen": u["is_frozen"],
            "card_scheme": u.get("card", {}).get("scheme", "VISA")
        } for u in all_users
    ]
    return jsonify({
        "success": True,
        "transactions": feed["transactions"],
        "alerts": feed["alerts"],
        "accounts": safe_users
    })


@app.route("/api/admin/toggle-freeze", methods=["POST"])
def api_admin_freeze():
    data = request.get_json() or {}
    account_no = data.get("account_no")
    freeze_state = data.get("freeze_state")

    if account_no is None or freeze_state is None:
        return jsonify({"success": False, "message": "Invalid parameters."}), 400

    success = bank.set_account_freeze_status(account_no, bool(freeze_state))
    status_text = "frozen" if freeze_state else "unfrozen"
    return jsonify({
        "success": success,
        "message": f"Account {account_no} successfully {status_text}."
    })


@app.route("/api/admin/export/<fmt>", methods=["GET"])
def api_admin_export(fmt):
    feed = bank.get_admin_audit_feed()
    all_users = bank.get_all_accounts()

    if fmt == "json":
        payload = {
            "exported_at": config.BANK_NAME,
            "accounts": all_users,
            "transactions": feed["transactions"],
            "security_alerts": feed["alerts"]
        }
        buf = io.BytesIO(json.dumps(payload, indent=4).encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name="Vaultly_Audit_Backup.json")

    # Default CSV Export of Transactions & Accounts
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["=== VAULTLY REGISTERED ACCOUNTS ==="])
    cw.writerow(["Account No", "Holder Name", "Email", "Balance (PKR)", "Status", "Card Network"])
    for u in all_users:
        cw.writerow([
            u["account_no"],
            u["name"],
            u["email"],
            u["balance"],
            "FROZEN" if u["is_frozen"] else "ACTIVE",
            u.get("card", {}).get("scheme", "VISA")
        ])

    cw.writerow([])
    cw.writerow(["=== VAULTLY TRANSACTION LEDGER ==="])
    cw.writerow(["Txn ID", "Sender Name", "Sender Acc", "Receiver Name", "Receiver Acc", "Bank", "Amount", "Tax", "Timestamp"])
    for t in feed["transactions"]:
        cw.writerow([
            t.get("txn_id"),
            t.get("sender_name", "-"),
            t.get("sender_acc"),
            t.get("receiver_name") or "External Account",
            t.get("receiver_acc"),
            t.get("bank_name"),
            t.get("amount"),
            t.get("tax", 0),
            t.get("timestamp")
        ])

    cw.writerow([])
    cw.writerow(["=== SECURITY & AML ALERTS ==="])
    cw.writerow(["Type", "Account No", "Details", "Timestamp"])
    for a in feed["alerts"]:
        cw.writerow([a.get("type"), a.get("account_no"), a.get("detail"), a.get("timestamp")])

    buf = io.BytesIO(si.getvalue().encode("utf-8"))
    buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name="Vaultly_Master_Audit_Report.csv")


if __name__ == "__main__":
    local_ip = get_local_ip()
    port = 5000
    print("=" * 65)
    print(f" {config.BANK_NAME} - Enterprise Online")
    print("=" * 65)
    print(f" -> Local Terminal:  http://127.0.0.1:{port}")
    print(f" -> Mobile Network:  http://{local_ip}:{port}")
    print(f" -> Admin Command:   http://{local_ip}:{port}/admin")
    print("=" * 65)
    app.run(host="0.0.0.0", port=port, debug=False)