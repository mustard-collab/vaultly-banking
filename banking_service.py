# banking_service.py
"""
VAULTLY Banking Core Service (v2.0 Enterprise)
- Persistent JSON Storage (Auto-Save & Load)
- Visa & Mastercard Dynamic Virtual Card Provisioning
- Date-Range Filtered Encrypted PDF Statements
- Inter-Bank (30 Pakistani Banks) & Same-Bank Logic
"""

import os
import json
import time
import uuid
import secrets
import threading
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any

from dsa_core import HashTable, TransactionLedger, SlidingWindowVelocity, DirectedGraph, MinHeap
from security_engine import SecurityEngine, PDFStatementEngine, MailerService

DB_FILE = "/tmp/vaultly_database.json"

PAKISTAN_BANKS = [
    "VAULTLY (Same Bank - Free)",
    "Meezan Bank Limited",
    "Habib Bank Limited (HBL)",
    "United Bank Limited (UBL)",
    "MCB Bank Limited",
    "Allied Bank Limited (ABL)",
    "Bank Alfalah",
    "Faysal Bank",
    "Standard Chartered Bank (SCB)",
    "Askari Bank",
    "Bank Al-Habib",
    "Habib Metropolitan Bank",
    "Dubai Islamic Bank (DIB)",
    "Bank of Punjab (BOP)",
    "Bank of Khyber (BOK)",
    "Soneri Bank",
    "JS Bank",
    "Sindh Bank",
    "Al Baraka Bank",
    "First Women Bank",
    "Samba Bank",
    "National Bank of Pakistan (NBP)",
    "Summit Bank",
    "Silkbank",
    "NayaPay",
    "SadaPay",
    "Easypaisa (Telenor Microfinance)",
    "JazzCash (Mobilink Microfinance)",
    "U Microfinance Bank (UPaisa)",
    "Raast Instant Payment Engine",
    "FINCA Microfinance Bank"
]

UTILITY_COMPANIES = [
    "K-Electric (Karachi Power)",
    "Sui Southern Gas Company (SSGC)",
    "Sui Northern Gas Pipelines (SNGPL)",
    "PTCL Landline & Broadband",
    "LESCO (Lahore Electric)",
    "FESCO (Faisalabad Electric)",
    "IESCO (Islamabad Electric)",
    "Water & Sanitation Agency (WASA)",
    "StormFiber Internet",
    "Nayatel Fiber Optic"
]


class BankingService:
    def __init__(self):
        self.users_table = HashTable(capacity=128)
        self.acc_to_email = HashTable(capacity=128)
        self.ledger = TransactionLedger()
        self.aml_graph = DirectedGraph()
        self.velocity_monitors: Dict[str, SlidingWindowVelocity] = {}
        self.otp_heap = MinHeap()
        self.active_otps: Dict[str, Tuple[str, float]] = {}
        self.pending_registrations: Dict[str, Dict[str, Any]] = {}
        self.security_alerts: List[Dict[str, Any]] = []

        # Load persistent data if exists
        self.load_database()

    def _async_send_email(self, func, *args):
        threading.Thread(target=func, args=args, daemon=True).start()

    # ==========================================
    # PERSISTENT STORAGE ENGINE (AUTO-SAVE)
    # ==========================================
    def save_database(self):
        try:
            data = {
                "users": self.users_table.to_list(),
                "transactions": self.ledger.get_all_forward(),
                "alerts": self.security_alerts
            }
            with open(DB_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"[DB SAVE ERROR]: {e}")

    def load_database(self):
        if not os.path.exists(DB_FILE):
            return
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for u in data.get("users", []):
                email_key = u["email"]
                acc_no = u["account_no"]
                self.users_table.put(email_key, u)
                self.acc_to_email.put(acc_no, email_key)
                self.velocity_monitors[acc_no] = SlidingWindowVelocity(window_seconds=60.0, max_requests=4)
            for tx in data.get("transactions", []):
                self.ledger.append(tx)
                if tx.get("is_same_bank"):
                    self.aml_graph.add_edge(tx.get("sender_acc", ""), tx.get("receiver_acc", ""))
            self.security_alerts = data.get("alerts", [])
        except Exception as e:
            print(f"[DB LOAD ERROR]: {e}")

    # ==========================================
    # REGISTRATION WITH 2FA & CARD SCHEME CHOICE
    # ==========================================
    def initiate_registration(self, full_name: str, email: str, raw_password: str, initial_deposit: float = 50000.0, card_scheme: str = "VISA") -> Tuple[bool, str]:
        email_key = email.strip().lower()
        if self.users_table.contains(email_key):
            return False, "An account with this email already exists."

        hashed_pw, salt = SecurityEngine.hash_password(raw_password)
        self.pending_registrations[email_key] = {
            "name": full_name.strip(),
            "email": email_key,
            "password_hash": hashed_pw,
            "salt": salt,
            "deposit": float(initial_deposit),
            "card_scheme": card_scheme.upper()
        }

        otp = SecurityEngine.generate_otp()
        expiry = time.time() + 180.0
        self.active_otps[email_key] = (otp, expiry)
        self.otp_heap.push(expiry, (email_key, otp))

        self._async_send_email(MailerService.send_otp_email, email_key, otp)
        return True, "Verification code sent to your email."

    def _generate_card_number(self, scheme: str, account_no: str) -> str:
        if scheme.upper() == "MASTERCARD":
            prefix = f"5{secrets.randbelow(5) + 1}{secrets.randbelow(90) + 10}"
        else:
            prefix = f"4{secrets.randbelow(900) + 100}"
        mid1 = f"{secrets.randbelow(9000) + 1000}"
        mid2 = f"{secrets.randbelow(9000) + 1000}"
        return f"{prefix} {mid1} {mid2} {account_no[-4:]}"

    def finalize_registration(self, email: str, otp_code: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        email_key = email.strip().lower()
        now = time.time()

        record = self.active_otps.get(email_key)
        if not record:
            return False, None, "No active registration request or code expired."

        stored_otp, expiry = record
        if now > expiry:
            del self.active_otps[email_key]
            self.pending_registrations.pop(email_key, None)
            return False, None, "Verification code expired. Please register again."

        if stored_otp != otp_code.strip():
            return False, None, "Incorrect OTP code."

        del self.active_otps[email_key]
        reg_data = self.pending_registrations.pop(email_key, None)
        if not reg_data:
            return False, None, "Registration data lost. Try again."

        account_no = f"88{secrets.randbelow(90000000) + 10000000}"
        while self.acc_to_email.contains(account_no):
            account_no = f"88{secrets.randbelow(90000000) + 10000000}"

        scheme = reg_data.get("card_scheme", "VISA")
        card_number = self._generate_card_number(scheme, account_no)
        cvv = f"{secrets.randbelow(900) + 100}"
        expiry_card = "11/31"

        user_record = {
            "name": reg_data["name"],
            "email": email_key,
            "account_no": account_no,
            "password_hash": reg_data["password_hash"],
            "salt": reg_data["salt"],
            "balance": float(reg_data["deposit"]),
            "is_frozen": False,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "card": {
                "scheme": scheme,
                "card_number": card_number,
                "cvv": cvv,
                "expiry": expiry_card,
                "is_active": True,
                "intl_allowed": False,
                "online_limit": 100000
            }
        }

        self.users_table.put(email_key, user_record)
        self.acc_to_email.put(account_no, email_key)
        self.velocity_monitors[account_no] = SlidingWindowVelocity(window_seconds=60.0, max_requests=4)

        initial_tx = {
            "txn_id": f"TXN-{uuid.uuid4().hex[:8].upper()}",
            "is_same_bank": True,
            "sender_name": "VAULTLY Treasury",
            "sender_acc": "VAULTLY_CENTRAL",
            "receiver_acc": account_no,
            "receiver_name": reg_data["name"],
            "bank_name": "VAULTLY (Internal)",
            "type": "INITIAL_DEPOSIT",
            "amount": reg_data["deposit"],
            "tax": 0.0,
            "total": reg_data["deposit"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "COMPLETED"
        }
        self.ledger.append(initial_tx)
        self.save_database()

        return True, user_record, "Account authorized successfully!"

    # ==========================================
    # LOGIN & 2FA
    # ==========================================
    def initiate_login(self, email: str, raw_password: str) -> Tuple[bool, str]:
        email_key = email.strip().lower()
        user = self.users_table.get(email_key)
        if not user:
            return False, "Invalid account credentials."

        if user["is_frozen"]:
            return False, "Account locked due to security anomalies."

        if not SecurityEngine.verify_password(user["password_hash"], user["salt"], raw_password):
            return False, "Invalid account credentials."

        otp = SecurityEngine.generate_otp()
        expiry = time.time() + 180.0
        self.active_otps[email_key] = (otp, expiry)
        self.otp_heap.push(expiry, (email_key, otp))

        self._async_send_email(MailerService.send_otp_email, email_key, otp)
        return True, "One-time passcode dispatched to your email."

    def verify_login_otp(self, email: str, otp_attempt: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        email_key = email.strip().lower()
        now = time.time()

        record = self.active_otps.get(email_key)
        if not record:
            return False, None, "No active login or OTP expired."

        stored_otp, expiry = record
        if now > expiry:
            del self.active_otps[email_key]
            return False, None, "OTP expired. Request again."

        if stored_otp != otp_attempt.strip():
            return False, None, "Incorrect OTP code."

        del self.active_otps[email_key]
        user = self.users_table.get(email_key)
        return True, user, "Session authenticated."

    # ==========================================
    # SMART PAYMENTS & TRANSFERS
    # ==========================================
    def execute_transfer(self, sender_acc: str, target_bank: str, receiver_acc: str, amount: float) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        amount = float(amount)
        if amount <= 0:
            return False, "Amount must be strictly positive.", None

        sender_email = self.acc_to_email.get(sender_acc)
        if not sender_email:
            return False, "Invalid sender account.", None

        sender = self.users_table.get(sender_email)
        if sender["is_frozen"]:
            return False, "Sender account is restricted/frozen.", None

        is_same_bank = ("VAULTLY" in target_bank)
        tax = 0.0 if is_same_bank else 30.0
        total_deduction = amount + tax

        if sender["balance"] < total_deduction:
            return False, f"Insufficient funds. Required: PKR {total_deduction:,.2f} (Includes PKR {tax:.0f} Tax). Available: PKR {sender['balance']:,.2f}", None

        # Fraud Check 1: Velocity
        velocity = self.velocity_monitors.get(sender_acc)
        if velocity and not velocity.record_and_evaluate():
            sender["is_frozen"] = True
            alert = {
                "type": "BURST_ATTACK",
                "account_no": sender_acc,
                "detail": f"Account {sender_acc} triggered burst velocity (>4 txns/60s). Account frozen.",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            self.security_alerts.append(alert)
            self.save_database()
            return False, "Fraud Alert: High velocity transfer burst. Account locked.", None

        if is_same_bank:
            if sender_acc == receiver_acc:
                return False, "Cannot transfer funds to yourself.", None

            receiver_email = self.acc_to_email.get(receiver_acc)
            if not receiver_email:
                return False, "Beneficiary account not found in Vaultly system.", None

            receiver = self.users_table.get(receiver_email)
            if receiver["is_frozen"]:
                return False, "Beneficiary account is restricted.", None

            # Fraud Check 2: Cycle Detection
            if self.aml_graph.detects_cycle_if_added(sender_acc, receiver_acc):
                sender["is_frozen"] = True
                alert = {
                    "type": "CIRCULAR_LAUNDERING",
                    "account_no": sender_acc,
                    "detail": f"Circular loop detected: {sender_acc} -> {receiver_acc}. Blocked.",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                self.security_alerts.append(alert)
                self.save_database()
                return False, "Security Alert: Circular fund movement pattern detected by AML Graph.", None

            sender["balance"] -= total_deduction
            receiver["balance"] += amount
            self.aml_graph.add_edge(sender_acc, receiver_acc)
            receiver_display_name = receiver["name"]
        else:
            sender["balance"] -= total_deduction
            receiver_display_name = None

        txn_id = f"TXN-{uuid.uuid4().hex[:8].upper()}"
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        receipt_data = {
            "txn_id": txn_id,
            "is_same_bank": is_same_bank,
            "sender_name": sender["name"],
            "sender_acc": sender_acc,
            "receiver_acc": receiver_acc,
            "receiver_name": receiver_display_name,
            "bank_name": target_bank,
            "amount": amount,
            "tax": tax,
            "total": total_deduction,
            "timestamp": ts,
            "status": "COMPLETED / SETTLED"
        }

        self.ledger.append(receipt_data)
        self.save_database()
        return True, "Payment settled successfully.", receipt_data

    # ==========================================
    # UTILITY BILL PAYMENTS
    # ==========================================
    def pay_utility_bill(self, account_no: str, company: str, consumer_no: str, amount: float) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        amount = float(amount)
        if amount <= 0:
            return False, "Invalid bill amount.", None

        email = self.acc_to_email.get(account_no)
        if not email:
            return False, "Account not found.", None

        user = self.users_table.get(email)
        if user["is_frozen"]:
            return False, "Account is frozen.", None

        if user["balance"] < amount:
            return False, f"Insufficient balance. Available: PKR {user['balance']:,.2f}", None

        user["balance"] -= amount
        txn_id = f"BILL-{uuid.uuid4().hex[:8].upper()}"
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        bill_receipt = {
            "txn_id": txn_id,
            "is_same_bank": False,
            "sender_name": user["name"],
            "sender_acc": account_no,
            "receiver_acc": f"Ref #{consumer_no}",
            "receiver_name": company,
            "bank_name": "Utility Bill Direct",
            "amount": amount,
            "tax": 0.0,
            "total": amount,
            "timestamp": ts,
            "status": "BILL PAID & CONFIRMED"
        }

        self.ledger.append(bill_receipt)
        self.save_database()
        return True, f"Bill for {company} paid successfully.", bill_receipt

    # ==========================================
    # VIRTUAL CARD CONTROLS (VISA / MASTERCARD)
    # ==========================================
    def update_card_settings(self, account_no: str, is_active: bool, intl_allowed: bool, online_limit: float, scheme: Optional[str] = None) -> bool:
        email = self.acc_to_email.get(account_no)
        if not email:
            return False
        user = self.users_table.get(email)
        if user and "card" in user:
            user["card"]["is_active"] = bool(is_active)
            user["card"]["intl_allowed"] = bool(intl_allowed)
            user["card"]["online_limit"] = float(online_limit)
            if scheme and scheme.upper() in ("VISA", "MASTERCARD"):
                if user["card"].get("scheme") != scheme.upper():
                    user["card"]["scheme"] = scheme.upper()
                    user["card"]["card_number"] = self._generate_card_number(scheme.upper(), account_no)
            self.save_database()
            return True
        return False

    # ==========================================
    # HISTORY & DATE-FILTERED STATEMENTS
    # ==========================================
    def get_account_history(self, account_no: str, limit: int = 40) -> List[Dict[str, Any]]:
        all_txns = self.ledger.get_all_reverse(limit=500)
        user_txns = []
        for tx in all_txns:
            if tx.get("sender_acc") == account_no:
                rec_name = tx.get("receiver_name")
                target_label = f"{rec_name} ({tx.get('receiver_acc')})" if rec_name else f"Account #{tx.get('receiver_acc')}"
                user_txns.append({
                    "txn_id": tx["txn_id"],
                    "direction": "DEBIT",
                    "label": f"Sent to {target_label}",
                    "bank": tx.get("bank_name", "VAULTLY"),
                    "amount": tx["amount"],
                    "tax": tx.get("tax", 0.0),
                    "timestamp": tx["timestamp"]
                })
            elif tx.get("receiver_acc") == account_no:
                user_txns.append({
                    "txn_id": tx["txn_id"],
                    "direction": "CREDIT",
                    "label": f"Received from {tx.get('sender_name', 'Sender')} ({tx.get('sender_acc')})",
                    "bank": tx.get("bank_name", "VAULTLY"),
                    "amount": tx["amount"],
                    "tax": 0.0,
                    "timestamp": tx["timestamp"]
                })
            if len(user_txns) >= limit:
                break
        return user_txns

    def request_and_send_statement(self, account_no: str, start_date: str = None, end_date: str = None) -> Tuple[bool, str]:
        email = self.acc_to_email.get(account_no)
        if not email:
            return False, "Account number not found."

        user = self.users_table.get(email)
        history = self.get_account_history(account_no, limit=250)

        filtered_history = []
        for h in history:
            tx_date = h["timestamp"][:10]  # YYYY-MM-DD
            if start_date and tx_date < start_date:
                continue
            if end_date and tx_date > end_date:
                continue
            filtered_history.append({
                "txn_id": h["txn_id"],
                "type": h["direction"],
                "counterparty": h["label"],
                "amount": h["amount"],
                "timestamp": h["timestamp"]
            })

        pdf_buffer = PDFStatementEngine.generate_encrypted_statement(
            user_name=user["name"],
            account_no=user["account_no"],
            balance=user["balance"],
            transactions=filtered_history
        )

        self._async_send_email(MailerService.send_statement_email, user["email"], user["account_no"], pdf_buffer)
        period_str = f"from {start_date} to {end_date}" if (start_date and end_date) else "for all dates"
        return True, f"Encrypted PDF Statement ({period_str}) sent to {user['email']}. Password: last 4 digits of your account."

    # ==========================================
    # ADMIN
    # ==========================================
    def get_all_accounts(self) -> List[Dict[str, Any]]:
        return self.users_table.to_list()

    def get_admin_audit_feed(self) -> Dict[str, Any]:
        return {
            "transactions": self.ledger.get_all_reverse(limit=200),
            "alerts": self.security_alerts[::-1]
        }

    def set_account_freeze_status(self, account_no: str, freeze_state: bool) -> bool:
        email = self.acc_to_email.get(account_no)
        if not email:
            return False
        user = self.users_table.get(email)
        if user:
            user["is_frozen"] = freeze_state
            self.save_database()
            return True
        return False
