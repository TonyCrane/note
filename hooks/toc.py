import os
import re
import logging

import yaml
from jinja2 import Template

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.pages import Page
from mkdocs.structure.files import Files

from utils.toc import get_statistics, get_update_time

enabled = os.getenv("TOC", "1") == "1" or os.getenv("FULL", "0") == "true"
logger = logging.getLogger("mkdocs.hooks.toc")

if enabled:
    logger.info("hook - toc is loaded and enabled")
else:
    logger.info("hook - toc is disabled")

HOOKS_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(HOOKS_DIR, "templates/toc.html")
IGNORE_DIR = os.path.join(HOOKS_DIR, "..", ".ignored-commits")

with open(TEMPLATE_DIR, "r", encoding="utf-8") as file:
    TEMPLATE = file.read()

# IGNORE_COMMITS = [
#     {"cs/system/cs1/topic1.md": "859970b504aa527030420ff9fbfffdb1b62d71f1"},
# ]

with open(IGNORE_DIR, "r", encoding="utf-8") as file:
    IGNORE_COMMITS = [
        line.strip() for line in file if line.strip() and not line.startswith("#")
    ]

def on_page_markdown(
    markdown: str, page: Page, config: MkDocsConfig, files: Files, **kwargs
) -> str:
    if not enabled:
        return markdown
    if "{{ BEGIN_TOC }}" not in markdown or "{{ END_TOC }}" not in markdown:
        return markdown
    toc_yml = markdown.split("{{ BEGIN_TOC }}")[1].split("{{ END_TOC }}")[0]
    toc = yaml.load(toc_yml, Loader=yaml.FullLoader)
    toc_items = _get_toc_items(toc, os.path.dirname(page.file.abs_src_path))
    toc_html = Template(TEMPLATE).render(items=toc_items)
    markdown = re.sub(
        r"\{\{ BEGIN_TOC \}\}.*\{\{ END_TOC \}\}",
        toc_html,
        markdown,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return markdown


def _get_toc_items(toc: dict, base: str) -> list:
    ret = []
    for i, part in enumerate(toc):
        item = dict()
        item["n"] = i
        title = list(part.keys())[0]
        if "[note]" in title:
            item["note"] = True
            title = title.replace("[note]", "")
        else:
            item["note"] = False
        item["title"] = title
        details = []
        for d in part[list(part.keys())[0]]:
            key = list(d.keys())[0]
            value = d[key]
            if key == "index":
                item["link"] = value
                continue
            detail = dict()
            t = key
            detail["note"] = False
            detail["lab"] = False
            if "[note]" in t:
                detail["note"] = True
                t = t.replace("[note]", "")
            if "[lab]" in t:
                detail["lab"] = True
                t = t.replace("[lab]", "")
            detail["title"] = t
            detail["link"] = value
            detail["words"], detail["codes"], detail["read_time"] = get_statistics(
                value, base
            )
            detail["update_time"] = get_update_time(value, base, IGNORE_COMMITS)
            if "🔒" in t:
                detail["lock"] = True
            details.append(detail)
        details.sort(key=lambda x: x["update_time"], reverse=True)
        item["contents"] = details
        ret.append(item)
    return ret
