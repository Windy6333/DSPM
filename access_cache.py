"""
access_cache.py — In-memory set of external user folder roots.

Build  : store exact normalised folder paths of external users (daily sync).
Lookup : generate all ancestor paths of a filepath and check if any
         ancestor exists in the set — isdisjoint() short-circuits on
         first match.

  cache   = { "/usr/folder/", "/clients/acme/" }

  filepath  "/usr/folder/invoices/data.csv"
  ancestors { "/usr/", "/usr/folder/", "/usr/folder/invoices/" }

  ancestors & cache → { "/usr/folder/" } → not empty → True

Normalisation is handled upstream in path_utils.py before anything
reaches the cache, so all paths here are already clean.
"""

import logging

logger  = logging.getLogger(__name__)
_cache: set[str] = set()


def rebuild(external_folders: list[str]):
    """
    Store exact external folder roots.
    Called once after each daily SFTP user sync.
    Single reference swap — atomic, no lock needed.
    """
    global _cache
    _cache = {_ensure_trailing_slash(f) for f in external_folders if f}
    logger.info("Access cache rebuilt: %d external folder roots.", len(_cache))


def has_external_access(filepath: str) -> bool:
    """
    Return True if any ancestor folder of filepath is a known external root.
    isdisjoint() short-circuits on first match.
    """
    return not _ancestors(filepath).isdisjoint(_cache)


def is_empty() -> bool:
    return len(_cache) == 0


def _ensure_trailing_slash(path: str) -> str:
    return path.rstrip("/") + "/"


def _ancestors(filepath: str) -> set[str]:
    """
    Return all ancestor folder paths of a filepath.

    "/usr/folder/invoices/data.csv"
      → { "/usr/", "/usr/folder/", "/usr/folder/invoices/" }
    """
    folder = filepath.rsplit("/", 1)[0]
    parts  = folder.strip("/").split("/")
    result = set()
    for i in range(1, len(parts) + 1):
        segment = "/".join(parts[:i])
        if segment:
            result.add("/" + segment + "/")
    return result
