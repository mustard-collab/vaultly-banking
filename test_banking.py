# test_banking.py
from banking_service import BankingService

print("--- Testing VAULTLY Core Banking Service ---")
bank = BankingService()

# 1. Register two accounts
u1 = bank.register_account("Mustafa Khan", "mustafa@test.com", "SecretPass123", 50000.0)
u2 = bank.register_account("Faizan Peer", "faizan@test.com", "SecurePass456", 20000.0)
print(f"[OK] Registered Users: {u1['account_no']} and {u2['account_no']}")

# 2. Test Transfer
success, msg = bank.execute_transfer(u1['account_no'], u2['account_no'], 15000.0)
assert success is True
print(f"[OK] Transfer Success: {msg}")

# 3. Test Insufficient Balance
fail_res, fail_msg = bank.execute_transfer(u1['account_no'], u2['account_no'], 900000.0)
assert fail_res is False
print(f"[OK] Balance Guard Handled: {fail_msg}")

# 4. Test Burst Rate-Limiting (Rapid Transfers)
print("[Testing Burst Velocity Limiter...]")
bank.execute_transfer(u1['account_no'], u2['account_no'], 100)
bank.execute_transfer(u1['account_no'], u2['account_no'], 100)
bank.execute_transfer(u1['account_no'], u2['account_no'], 100)
blocked_res, blocked_msg = bank.execute_transfer(u1['account_no'], u2['account_no'], 100)
assert blocked_res is False
print(f"[OK] Anti-Fraud Engine Triggered: {blocked_msg}")

print("\nALL BANKING SERVICES VERIFIED SUCCESSFULLY!")