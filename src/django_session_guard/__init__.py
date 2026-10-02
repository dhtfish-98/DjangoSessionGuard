"""Static session/CSRF review; no Django dependency or settings execution."""
from .contracts import Limits
from .review import review_settings
__all__ = ["Limits", "review_settings"]
__version__ = "0.1.0"
