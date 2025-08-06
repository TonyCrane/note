import os
import logging

from bs4 import BeautifulSoup

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.nav import Page

from typing import Optional

enabled = os.getenv("THEME", "0") == "1" or os.getenv("FULL", "0") == "true"
logger = logging.getLogger("mkdocs.hooks.theme_override")

if enabled:
    logger.info("hook - theme_override is loaded and enabled")
else:
    logger.info("hook - theme_override is disabled")


def on_post_page(output: str, *, page: Page, config: MkDocsConfig) -> Optional[str]:
    if not enabled:
        return output
    soup = BeautifulSoup(output, "lxml")

    navs = soup.select(
        ".md-nav--lifted>.md-nav__list>.md-nav__item>.md-nav>.md-nav__list>.md-nav__item"
    )
    for nav in navs:
        if nav.select("label") and nav.select("label")[0].text.strip() in [
            "misc",
            "blockchain",
            "crypto",
            "web",
            "reverse",
            "pwn",
        ]:
            nav["class"].append("md-nav__item--section")

    return str(soup)
