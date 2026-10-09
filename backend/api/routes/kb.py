"""Knowledge Base router."""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from knowledge_base.service import create_article, search_articles, list_by_category, get_all, suggest_for_ticket

router = APIRouter()

class ArticleCreate(BaseModel):
    title: str
    content: str
    category: str = "general"
    tags: list[str] = []

@router.get("/")
async def list_articles(limit: int = 50):
    return {"articles": get_all(limit), "total": len(get_all(limit))}

@router.get("/search")
async def search(q: str, limit: int = 10):
    return {"results": search_articles(q, limit), "query": q}

@router.post("/articles", status_code=201)
async def create(payload: ArticleCreate):
    article = create_article(payload.title, payload.content, payload.category, payload.tags)
    return article

@router.get("/suggest")
async def suggest(ticket_text: str):
    return {"suggestions": suggest_for_ticket(ticket_text)}

@router.get("/category/{category}")
async def by_category(category: str):
    return {"articles": list_by_category(category), "category": category}
