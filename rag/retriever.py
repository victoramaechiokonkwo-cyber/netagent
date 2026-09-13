"""TF-IDF retriever. No embeddings, no downloads, instant to build."""
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config import TFIDF_NGRAMS
from core.schema import RetrievedDoc
from rag.docs import ALL_DOCS, KnowledgeDoc


class Retriever:
    def __init__(self, docs: list[KnowledgeDoc] | None = None):
        self.docs = docs or ALL_DOCS
        self.vectorizer = TfidfVectorizer(
            ngram_range=TFIDF_NGRAMS,
            sublinear_tf=True,
            stop_words="english",
        )
        corpus = [d.indexed_text() for d in self.docs]
        self.matrix = self.vectorizer.fit_transform(corpus)

    def search(self, query: str, k: int = 4) -> list[RetrievedDoc]:
        if not query.strip():
            return []
        q = self.vectorizer.transform([query])
        sims = cosine_similarity(q, self.matrix)[0]
        order = np.argsort(-sims)[:k]
        out = []
        for i in order:
            if sims[i] <= 0.0:
                continue
            d = self.docs[i]
            out.append(RetrievedDoc(
                doc_id=d.doc_id,
                title=d.title,
                text=d.text,
                score=round(float(sims[i]), 4),
                tags=d.tags,
            ))
        return out

    def doc_by_id(self, doc_id: str) -> KnowledgeDoc | None:
        for d in self.docs:
            if d.doc_id == doc_id:
                return d
        return None