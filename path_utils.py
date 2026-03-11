import re
import logging
from config import Config

logger = logging.getLogger(__name__)


def normalise_upload_path(raw_path: str) -> str:
    # Normalise a Windows filepath from an EFT upload event.
    # EFT sends backslash paths with a long server prefix.
    # We strip the prefix, replace backslashes with forward slashes,
    # and lowercase everything so paths match the EFT user API format.
    if not raw_path:
        return ""

    # collapse all backslash variants into forward slash
    path = re.sub(r'[\\]+', '/', raw_path)

    # normalise the prefix the same way then strip it
    prefix = re.sub(r'[\\]+', '/', Config.SFTP_PATH_PREFIX).lower().rstrip("/")
    path   = path.lower()

    if prefix and path.startswith(prefix):
        path = path[len(prefix):]

    # ensure single leading slash, no trailing slash
    path = "/" + path.lstrip("/").rstrip("/")

    logger.debug("Path normalised: %s -> %s", raw_path, path)
    return path


def normalise_folder_path(raw_folder: str) -> str:
    # Normalise a folder path from the EFT user API.
    # Input  : /Usr/folder/  ->  Output : /usr/folder/
    if not raw_folder:
        return ""
    path = raw_folder.replace("\\", "/").lower()
    path = "/" + path.strip("/") + "/"
    return path
