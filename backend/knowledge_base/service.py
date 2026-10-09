"""
Knowledge Base — self-service article store.

Competitive gap: 69% of users prefer self-service but only 30% succeed.
ResilientAI's KB is auto-seeded from ticket resolutions — every AI-resolved
ticket generates a candidate article. No manual authoring required to start.
"""
import uuid
from datetime import datetime, timezone

_articles: list[dict] = []

_CATEGORY_KEYWORDS = {
    "connectivity": ["vpn", "network", "internet", "wifi", "disconnect", "connect"],
    "access":       ["password", "login", "mfa", "locked", "reset", "account"],
    "software":     ["install", "crash", "app", "application", "update", "teams", "slack", "outlook"],
    "disk":         ["disk", "storage", "full", "cleanup", "space"],
    "hardware":     ["printer", "monitor", "keyboard", "mouse", "headset", "webcam"],
    "security":     ["threat", "virus", "malware", "phishing", "suspicious"],
}


def _infer_category(text: str) -> str:
    lower = text.lower()
    for cat, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return cat
    return "general"


def create_article(
    title: str,
    content: str,
    category: str,
    tags: list[str],
) -> dict:
    article = {
        "id": f"kb-{uuid.uuid4().hex[:8]}",
        "title": title,
        "content": content,
        "category": category,
        "tags": [t.lower() for t in tags],
        "views": 0,
        "helpful_votes": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _articles.append(article)
    return article


def search_articles(query: str, limit: int = 10) -> list[dict]:
    q = query.lower()
    results = []
    for a in _articles:
        score = 0
        if q in a["title"].lower():     score += 3
        if q in a["content"].lower():   score += 2
        if any(q in t for t in a["tags"]): score += 2
        if q in a["category"].lower():  score += 1
        if score > 0:
            results.append({**a, "_score": score})
    results.sort(key=lambda x: x["_score"], reverse=True)
    return [{k: v for k, v in r.items() if k != "_score"} for r in results[:limit]]


def list_by_category(category: str) -> list[dict]:
    return [a for a in _articles if a["category"] == category]


def suggest_for_ticket(ticket_text: str, limit: int = 3) -> list[dict]:
    """Auto-suggest knowledge base articles for an incoming ticket."""
    words = ticket_text.lower().split()
    scored = []
    for a in _articles:
        score = sum(
            3 if w in a["title"].lower() else
            1 if w in a["content"].lower() else
            2 if w in a["tags"] else 0
            for w in words
        )
        if score > 0:
            scored.append({**a, "_score": score})
    scored.sort(key=lambda x: x["_score"], reverse=True)
    return [{k: v for k, v in r.items() if k != "_score"} for r in scored[:limit]]


def seed_from_ticket_resolution(title: str, resolution: str, category: str = "") -> dict:
    """Auto-create a KB article from an AI ticket resolution."""
    cat = category or _infer_category(f"{title} {resolution}")
    tags = [w for w in title.lower().split() if len(w) > 3][:5]
    return create_article(
        title=f"How to: {title}",
        content=resolution,
        category=cat,
        tags=tags,
    )


def get_all(limit: int = 100) -> list[dict]:
    return _articles[:limit]
