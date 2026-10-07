"""
client/token_generator.py
-------------------------
Generates search tokens (trapdoors) for querying the encrypted index.

EXISTING TECHNIQUE:
    Search token generation via PRF is standard in SSE constructions.
    Reference: Curtmola et al. (CCS 2006), Cash et al. OXT (CRYPTO 2013).

OUR ARCHITECTURAL INTEGRATION:
    We integrate token generation with ephemeral query-key lifecycle
    and support both single-keyword and Boolean AND token generation.
"""

from crypto.prf import prf, generate_search_token, compute_index_label
from crypto.utils import secure_random_bytes


class SearchToken:
    """Represents a search token for a single keyword."""

    def __init__(self, keyword_token: bytes, keyword_index: int = 0):
        self.token = keyword_token
        self.keyword_index = keyword_index

    def compute_label(self, counter: int) -> str:
        """Compute the index label for a given counter position."""
        return prf(self.token, f"label:{counter}".encode('utf-8')).hex()


class SingleSearchTokenSet:
    """Token set for a single-keyword query."""

    def __init__(self, token: SearchToken, query_id: str):
        self.token = token
        self.query_id = query_id
        self.query_type = "SINGLE_KEYWORD"


class BooleanSearchTokenSet:
    """
    Token set for a Boolean AND query (OXT-inspired).

    OUR ARCHITECTURAL INTEGRATION:
        The first keyword is treated as the "least frequent" candidate
        (s-term in OXT terminology). Remaining keywords are cross-tags
        (x-terms) used for intersection filtering.
    """

    def __init__(self, s_token: SearchToken, x_tokens: list, query_id: str):
        self.s_token = s_token        # Primary/candidate keyword token
        self.x_tokens = x_tokens      # List of SearchTokens for filtering
        self.query_id = query_id
        self.query_type = "BOOLEAN_AND"

    @property
    def all_tokens(self) -> list:
        return [self.s_token] + self.x_tokens


class TokenGenerator:
    """
    Generates search tokens using the ephemeral query key.

    Token generation flow:
        query_key + keyword -> PRF -> search_token
    """

    def __init__(self, index_key: bytes):
        """
        Args:
            index_key: The index key derived from master key
        """
        self._index_key = index_key

    def generate_single_token(self, query_key: bytes, keyword: str) -> SingleSearchTokenSet:
        """
        Generate a search token for a single-keyword query.

        Args:
            query_key: Ephemeral query key
            keyword: Normalized keyword

        Returns:
            SingleSearchTokenSet
        """
        token_bytes = generate_search_token(query_key, keyword)
        token = SearchToken(token_bytes, keyword_index=0)
        query_id = secure_random_bytes(8).hex()

        return SingleSearchTokenSet(token=token, query_id=query_id)

    def generate_boolean_tokens(self, query_key: bytes,
                                keywords: list) -> BooleanSearchTokenSet:
        """
        Generate tokens for a Boolean AND query (OXT-inspired).

        OUR ARCHITECTURAL INTEGRATION:
            - First keyword becomes the s-term (candidate selector)
            - Remaining keywords become x-terms (filters)
            - In a full OXT, cross-tags involve bilinear maps;
              our prototype uses HMAC-based tokens for intersection.

        Args:
            query_key: Ephemeral query key
            keywords: List of normalized keywords

        Returns:
            BooleanSearchTokenSet
        """
        query_id = secure_random_bytes(8).hex()

        # First keyword = s-term (candidate)
        s_token_bytes = generate_search_token(query_key, keywords[0])
        s_token = SearchToken(s_token_bytes, keyword_index=0)

        # Remaining keywords = x-terms (filters)
        x_tokens = []
        for i, kw in enumerate(keywords[1:], start=1):
            x_token_bytes = generate_search_token(query_key, kw)
            x_tokens.append(SearchToken(x_token_bytes, keyword_index=i))

        return BooleanSearchTokenSet(
            s_token=s_token,
            x_tokens=x_tokens,
            query_id=query_id
        )

    def get_index_key(self) -> bytes:
        """Return the index key for server-side operations."""
        return self._index_key
