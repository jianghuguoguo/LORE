# -*- coding: utf-8 -*-
# This file is a compatibility shim. The real implementation has moved to src.layer0.
# Please update your imports: from src.layer0.log_adapter import ...
from src.layer0.log_adapter import LogAdapter, AdapterRegistry
__all__ = ["LogAdapter", "AdapterRegistry"]
