"""
client/query_processor.py
-------------------------
Parses and classifies user queries into single-keyword or Boolean AND.

OUR ARCHITECTURAL INTEGRATION:
    The query processor is part of our hybrid architecture that routes
    queries to the appropriate search path (basic SSE or OXT-inspired).
    Query parsing itself is not a cryptographic contribution.
"""

import re
from crypto.utils import normalize_keyword


class QueryParseError(Exception):
    """Raised when a query cannot be parsed."""
    pass


class ParsedQuery:
    """Represents a parsed search query."""

    SINGLE = "SINGLE_KEYWORD"
    BOOLEAN_AND = "BOOLEAN_AND"

    def __init__(self, query_type: str, keywords: list, raw_query: str):
        self.query_type = query_type
        self.keywords = keywords
        self.raw_query = raw_query

    @property
    def is_single(self) -> bool:
        return self.query_type == self.SINGLE

    @property
    def is_boolean(self) -> bool:
        return self.query_type == self.BOOLEAN_AND

    @property
    def keyword_count(self) -> int:
        return len(self.keywords)

    def __repr__(self):
        return f"ParsedQuery(type={self.query_type}, keywords={self.keywords})"


class QueryProcessor:
    """
    Processes user search queries and routes to the appropriate search mechanism.

    Supported query forms:
        Single keyword:    "diabetes"
        Boolean AND:       "diabetes AND doctor AND hospital"

    NOT supported (by design):
        OR queries:        "diabetes OR doctor"
        NOT queries:       "NOT diabetes"
        Nested:            "diabetes AND (doctor OR nurse)"
    """

    # Unsupported operators for clear error messages
    UNSUPPORTED_OPS = ['OR', 'NOT', '(', ')']

    def parse(self, raw_query: str) -> ParsedQuery:
        """
        Parse a raw query string into a ParsedQuery object.

        Args:
            raw_query: User's search query string

        Returns:
            ParsedQuery object

        Raises:
            QueryParseError: If the query is invalid or uses unsupported operators
        """
        if not raw_query or not raw_query.strip():
            raise QueryParseError("Empty query is not allowed.")

        query = raw_query.strip()

        # Check for unsupported Boolean operators
        for op in self.UNSUPPORTED_OPS:
            if op == '(' or op == ')':
                if op in query:
                    raise QueryParseError(
                        f"Nested/grouped queries are not supported. "
                        f"Only simple 'keyword' or 'keyword1 AND keyword2' queries are allowed."
                    )
            else:
                # Check for the operator as a standalone word
                pattern = r'\b' + re.escape(op) + r'\b'
                if re.search(pattern, query, re.IGNORECASE):
                    if op != 'AND':
                        raise QueryParseError(
                            f"'{op}' operator is not supported. "
                            f"Only conjunctive AND queries are supported."
                        )

        # Check if it's a Boolean AND query
        if re.search(r'\bAND\b', query, re.IGNORECASE):
            return self._parse_boolean_and(query)
        else:
            return self._parse_single(query)

    def _parse_single(self, query: str) -> ParsedQuery:
        """Parse a single-keyword query."""
        # Check for multiple words without AND
        words = query.split()
        if len(words) > 1:
            raise QueryParseError(
                f"Multiple words without 'AND' operator detected: '{query}'. "
                f"Use 'keyword1 AND keyword2' for Boolean queries."
            )

        keyword = normalize_keyword(query)
        if not keyword:
            raise QueryParseError(f"Query '{query}' normalizes to empty string.")

        return ParsedQuery(
            query_type=ParsedQuery.SINGLE,
            keywords=[keyword],
            raw_query=query
        )

    def _parse_boolean_and(self, query: str) -> ParsedQuery:
        """Parse a Boolean AND query."""
        # Split by AND (case-insensitive)
        parts = re.split(r'\s+AND\s+', query, flags=re.IGNORECASE)

        if len(parts) < 2:
            raise QueryParseError(
                f"Boolean AND query must have at least 2 keywords: '{query}'"
            )

        keywords = []
        for part in parts:
            keyword = normalize_keyword(part.strip())
            if not keyword:
                raise QueryParseError(
                    f"Empty keyword found in Boolean query: '{query}'"
                )
            keywords.append(keyword)

        # Check for duplicate keywords
        if len(keywords) != len(set(keywords)):
            raise QueryParseError(
                f"Duplicate keywords found in Boolean query: {keywords}"
            )

        return ParsedQuery(
            query_type=ParsedQuery.BOOLEAN_AND,
            keywords=keywords,
            raw_query=query
        )
