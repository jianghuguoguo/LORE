"""兼容入口：请改用 src.ragflow.uploader。"""
from src.ragflow.uploader import *  # noqa: F401,F403


if __name__ == "__main__":
    from src.ragflow.uploader import main

    raise SystemExit(main())
