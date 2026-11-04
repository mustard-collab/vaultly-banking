# dsa_core.py
"""
VAULTLY Core Data Structures Engine
Implemented completely from scratch without external dependencies.
"""

import time
from typing import Any, Optional, List, Tuple


# ==========================================
# 1. HASH TABLE WITH SEPARATE CHAINING
# ==========================================
class HashNode:
    def __init__(self, key: str, value: Any):
        self.key = key
        self.value = value
        self.next: Optional['HashNode'] = None


class HashTable:
    """
    Custom Hash Table implemented using polynomial rolling hash
    and separate chaining collision resolution.
    """
    def __init__(self, capacity: int = 64):
        self.capacity = capacity
        self.size = 0
        self.buckets: List[Optional[HashNode]] = [None] * self.capacity

    def _hash(self, key: str) -> int:
        hash_val = 0
        p = 31
        m = self.capacity
        p_pow = 1
        for char in str(key):
            hash_val = (hash_val + (ord(char) - ord('a') + 1) * p_pow) % m
            p_pow = (p_pow * p) % m
        return abs(hash_val)

    def put(self, key: str, value: Any) -> None:
        index = self._hash(key)
        node = self.buckets[index]

        if node is None:
            self.buckets[index] = HashNode(key, value)
            self.size += 1
            return

        prev = None
        while node is not None:
            if node.key == key:
                node.value = value
                return
            prev = node
            node = node.next

        if prev is not None:
            prev.next = HashNode(key, value)
            self.size += 1

    def get(self, key: str) -> Optional[Any]:
        index = self._hash(key)
        node = self.buckets[index]
        while node is not None:
            if node.key == key:
                return node.value
            node = node.next
        return None

    def contains(self, key: str) -> bool:
        return self.get(key) is not None

    def to_list(self) -> List[Any]:
        values = []
        for bucket in self.buckets:
            curr = bucket
            while curr:
                values.append(curr.value)
                curr = curr.next
        return values


# ==========================================
# 2. DOUBLY LINKED LIST (TRANSACTION LEDGER)
# ==========================================
class DLLNode:
    def __init__(self, data: dict):
        self.data = data
        self.prev: Optional['DLLNode'] = None
        self.next: Optional['DLLNode'] = None


class TransactionLedger:
    """
    Doubly Linked List allowing bidirectional traversal 
    for audit logs and e-statement generation.
    """
    def __init__(self):
        self.head: Optional[DLLNode] = None
        self.tail: Optional[DLLNode] = None
        self.count = 0

    def append(self, tx_data: dict) -> None:
        new_node = DLLNode(tx_data)
        if not self.head:
            self.head = self.tail = new_node
        else:
            new_node.prev = self.tail
            if self.tail:
                self.tail.next = new_node
            self.tail = new_node
        self.count += 1

    def get_all_reverse(self, limit: int = 100) -> List[dict]:
        """Returns transactions starting from the most recent to oldest."""
        result = []
        curr = self.tail
        while curr and len(result) < limit:
            result.append(curr.data)
            curr = curr.prev
        return result

    def get_all_forward(self) -> List[dict]:
        result = []
        curr = self.head
        while curr:
            result.append(curr.data)
            curr = curr.next
        return result


# ==========================================
# 3. SLIDING WINDOW DEQUE (FRAUD BURST DETECTOR)
# ==========================================
class DequeNode:
    def __init__(self, timestamp: float):
        self.timestamp = timestamp
        self.prev: Optional['DequeNode'] = None
        self.next: Optional['DequeNode'] = None


class SlidingWindowVelocity:
    """
    Maintains a sliding time window (e.g., 60 seconds).
    Detects if transactions per user exceed threshold.
    """
    def __init__(self, window_seconds: float = 60.0, max_requests: int = 5):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.head: Optional[DequeNode] = None
        self.tail: Optional[DequeNode] = None
        self.length = 0

    def _pop_left(self):
        if not self.head:
            return
        if self.head == self.tail:
            self.head = self.tail = None
        else:
            self.head = self.head.next
            if self.head:
                self.head.prev = None
        self.length -= 1

    def _append(self, timestamp: float):
        new_node = DequeNode(timestamp)
        if not self.tail:
            self.head = self.tail = new_node
        else:
            self.tail.next = new_node
            new_node.prev = self.tail
            self.tail = new_node
        self.length += 1

    def record_and_evaluate(self, now: Optional[float] = None) -> bool:
        """
        Records attempt. Returns True if transaction is allowed,
        False if velocity threshold breached (burst fraud).
        """
        if now is None:
            now = time.time()

        # Evict expired timestamps outside the sliding window
        while self.head and (now - self.head.timestamp > self.window_seconds):
            self._pop_left()

        if self.length >= self.max_requests:
            return False  # Threshold breached: Suspicious burst

        self._append(now)
        return True


# ==========================================
# 4. DIRECTED GRAPH & CYCLE DETECTION (MONEY LAUNDERING)
# ==========================================
class DirectedGraph:
    """
    Adjacency list graph representation with DFS cycle detection
    for identifying circular fund routing schemes.
    """
    def __init__(self):
        # account_no -> list of destination accounts
        self.adj: dict[str, list[str]] = {}

    def add_edge(self, u: str, v: str) -> None:
        if u not in self.adj:
            self.adj[u] = []
        if v not in self.adj:
            self.adj[v] = []
        self.adj[u].append(v)

    def detects_cycle_if_added(self, source: str, target: str) -> bool:
        """
        Tests if adding edge (source -> target) creates a cycle
        using Depth-First Search with visited and recursion stack sets.
        """
        # Temporary edge insertion
        if source not in self.adj:
            self.adj[source] = []
        if target not in self.adj:
            self.adj[target] = []

        self.adj[source].append(target)

        visited = set()
        rec_stack = set()
        has_cycle = False

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)

            for neighbor in self.adj.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        for node in list(self.adj.keys()):
            if node not in visited:
                if dfs(node):
                    has_cycle = True
                    break

        # Revert the temporary edge
        self.adj[source].remove(target)
        return has_cycle


# ==========================================
# 5. MIN-HEAP (PRIORITY QUEUE FOR EXPIRATIONS)
# ==========================================
class MinHeap:
    """
    Array-based Binary Min-Heap used for prioritizing 
    time-to-live items (e.g., OTP expiry tokens, scheduled actions).
    """
    def __init__(self):
        # elements: list of tuples (expiry_timestamp, data)
        self.heap: List[Tuple[float, Any]] = []

    def _parent(self, i: int) -> int:
        return (i - 1) // 2

    def _left(self, i: int) -> int:
        return 2 * i + 1

    def _right(self, i: int) -> int:
        return 2 * i + 2

    def push(self, expiry_time: float, data: Any) -> None:
        self.heap.append((expiry_time, data))
        self._sift_up(len(self.heap) - 1)

    def _sift_up(self, i: int) -> None:
        while i > 0 and self.heap[i][0] < self.heap[self._parent(i)][0]:
            p = self._parent(i)
            self.heap[i], self.heap[p] = self.heap[p], self.heap[i]
            i = p

    def peek(self) -> Optional[Tuple[float, Any]]:
        return self.heap[0] if self.heap else None

    def pop(self) -> Optional[Tuple[float, Any]]:
        if not self.heap:
            return None
        min_item = self.heap[0]
        last_item = self.heap.pop()
        if self.heap:
            self.heap[0] = last_item
            self._sift_down(0)
        return min_item

    def _sift_down(self, i: int) -> None:
        min_index = i
        n = len(self.heap)
        left = self._left(i)
        right = self._right(i)

        if left < n and self.heap[left][0] < self.heap[min_index][0]:
            min_index = left
        if right < n and self.heap[right][0] < self.heap[min_index][0]:
            min_index = right

        if i != min_index:
            self.heap[i], self.heap[min_index] = self.heap[min_index], self.heap[i]
            self._sift_down(min_index)

    def clean_expired(self, current_time: float) -> List[Any]:
        """Pops and returns all items that have reached their expiration time."""
        expired = []
        while self.heap and self.heap[0][0] <= current_time:
            expired.append(self.pop()[1])
        return expired