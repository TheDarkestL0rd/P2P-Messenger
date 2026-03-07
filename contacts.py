import json
import os
import time
from typing import Dict, Any, Optional

CONTACTS_FILE = "contacts.json"

def _default() -> Dict[str, Any]:
    return {"v": 1, "contacts": []}

def load_contacts() -> Dict[str, Any]:
    if not os.path.exists(CONTACTS_FILE):
        return _default()
    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_contacts(db: Dict[str, Any]) -> None:
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def get_contact(db: Dict[str, Any], peer_id: str) -> Optional[Dict[str, Any]]:
    for c in db.get("contacts", []):
        if c.get("peer_id") == peer_id:
            return c
    return None

def upsert_contact(db: Dict[str, Any], peer_id: str, ik_pub: str, name: str = "", trust: str = "TRUSTED") -> None:
    now = int(time.time())
    c = get_contact(db, peer_id)
    if c is None:
        db["contacts"].append({
            "peer_id": peer_id,
            "ik_pub": ik_pub,
            "name": name,
            "trust": trust,
            "created_at": now,
            "updated_at": now,
        })
    else:
        c["ik_pub"] = ik_pub
        if name:
            c["name"] = name
        c["trust"] = trust
        c["updated_at"] = now