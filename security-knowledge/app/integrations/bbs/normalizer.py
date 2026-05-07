def normalize_post(post: dict) -> dict:
    return {
        "id": post.get("id"),
        "title": post.get("title", ""),
        "content": post.get("content", ""),
        "author": post.get("author", ""),
        "published": post.get("published"),
    }
