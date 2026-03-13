import re
import logging
from config import Config

logger = logging.getLogger(__name__)


def normalise_upload_path(raw_path: str) -> str:
    """
    Normalise a Windows filepath from an EFT upload event.

    Steps:
    - Convert backslashes to forward slashes
    - Remove EFT server prefix
    - Lowercase path
    - Remove extra spaces from folder/file names
    - Ensure single leading slash
    """

    if not raw_path:
        return ""

    # convert backslashes to forward slash
    path = re.sub(r'[\\]+', '/', raw_path)

    # normalise prefix the same way
    prefix = re.sub(r'[\\]+', '/', Config.SFTP_PATH_PREFIX).lower().rstrip("/")

    path = path.lower()

    # remove server prefix
    if prefix and path.startswith(prefix):
        path = path[len(prefix):]

    # remove duplicate slashes
    path = re.sub(r'/+', '/', path)

    # trim leading/trailing spaces
    path = path.strip()

    # remove spaces from individual path parts
    parts = path.split("/")
    parts = [p.strip() for p in parts if p.strip()]

    path = "/" + "/".join(parts)

    logger.debug("Path normalised: %s -> %s", raw_path, path)

    return path


def normalise_folder_path(raw_folder: str) -> str:
    """
    Normalise folder path returned by EFT user API.

    Example:
    /Usr/folder/  ->  /usr/folder/
    """

    if not raw_folder:
        return ""

    path = raw_folder.replace("\\", "/").lower()

    # remove duplicate slashes
    path = re.sub(r'/+', '/', path)

    # trim spaces
    parts = path.strip("/").split("/")
    parts = [p.strip() for p in parts if p.strip()]

    path = "/" + "/".join(parts) + "/"

    return path
