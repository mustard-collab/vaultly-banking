# test_dsa.py
import time
from dsa_core import HashTable, TransactionLedger, SlidingWindowVelocity, DirectedGraph, MinHeap

print("--- Testing VAULTLY DSA Engines ---")

# 1. Test Hash Table
ht = HashTable()
ht.put("ACC1001", {"name": "Mustafa", "balance": 75000})
user = ht.get("ACC1001")
assert user["name"] == "Mustafa"
print("[OK] Custom Hash Table passed.")

# 2. Test Transaction Ledger (DLL)
ledger = TransactionLedger()
ledger.append({"txn_id": "TXN1", "amount": 500})
ledger.append({"txn_id": "TXN2", "amount": 1000})
recent = ledger.get_all_reverse()
assert recent[0]["txn_id"] == "TXN2"
print("[OK] Doubly Linked List Ledger passed.")

# 3. Test Graph Circular Detection
graph = DirectedGraph()
graph.add_edge("ACC1", "ACC2")
graph.add_edge("ACC2", "ACC3")
# Adding ACC3 -> ACC1 would create a cycle: ACC1 -> ACC2 -> ACC3 -> ACC1
cycle_detected = graph.detects_cycle_if_added("ACC3", "ACC1")
assert cycle_detected is True
print("[OK] Circular Money Laundering Graph passed.")

# 4. Test Sliding Window Rate Limiting (5 requests per 60s)
sw = SlidingWindowVelocity(window_seconds=60, max_requests=3)
assert sw.record_and_evaluate() is True
assert sw.record_and_evaluate() is True
assert sw.record_and_evaluate() is True
assert sw.record_and_evaluate() is False  # 4th burst request blocked
print("[OK] Sliding Window Velocity Fraud Engine passed.")

# 5. Test Min-Heap Expiry
heap = MinHeap()
now = time.time()
heap.push(now + 10, "VALID_OTP_1")
heap.push(now - 5, "EXPIRED_OTP_OLD")
expired = heap.clean_expired(now)
assert "EXPIRED_OTP_OLD" in expired
print("[OK] Min-Heap Expiry Priority Queue passed.")

print("\nALL DSA STRUCTURES PASSED VERIFICATION WITH ZERO ERRORS!")