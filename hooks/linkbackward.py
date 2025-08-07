import os
import re
import logging

from typing import Any, Dict

enabled = os.getenv("LINKBACKWARD", "0") == "1" or os.getenv("FULL", "0") == "true"
logger = logging.getLogger("mkdocs.hooks.linkbackward")

if enabled:
    logger.info("hook - linkbackward is loaded and enabled")
else:
    logger.info("hook - linkbackward is disabled")

WAIT_TIME = 0
REDIRS = [
    ("/ctf/steg/", "/ctf/misc/steg/"),
    ("/ctf/steg/image/", "/ctf/misc/steg/image/"),
    ("/ctf/steg/audio/", "/ctf/misc/steg/audio/"),
    ("/ctf/escapes/", "/ctf/misc/escapes/"),
    ("/ctf/escapes/pysandbox/", "/ctf/misc/escapes/pysandbox/"),
    ("/ctf/forensics/", "/ctf/misc/forensics/"),
    ("/ctf/forensics/mem/", "/ctf/misc/forensics/mem/"),
    ("/ctf/coding/", "/ctf/misc/coding/"),
    ("/ctf/qrcode/", "/ctf/misc/qrcode/"),
    ("/ctf/esolang/", "/ctf/misc/esolang/"),
    ("/cs/pl/c_cpp/", "/cs/pl/c_cpp/c/"),
    ("/hpc/", "/cs/hpc/hpc101/"),
    ("/hpc/hpc101/vectorized/", "/cs/hpc/hpc101/vectorized/"),
    ("/hpc/hpc101/gpu/", "/cs/hpc/hpc101/gpu/"),
    ("/hpc/hpc101/openmp/", "/cs/hpc/hpc101/openmp/"),
    ("/hpc/hpc101/mpi/", "/cs/hpc/hpc101/mpi/"),
    ("/hpc/hpc101/ml/", "/cs/hpc/hpc101/ml/"),
    ("/web/svg/", "/web/frontend/svg/"),
]


redirs = []
for src, dst in REDIRS:
    if not src.startswith("/"):
        src = "/" + src[1:]
    if not dst.startswith("/"):
        dst = "/" + dst[1:]
    if src.endswith("/"):
        src += "index.html"
    if dst.endswith("/"):
        dst += "index.html"
    if not src.endswith(".htm") and not src.endswith(".html"):
        src += "/index.html"
    if not dst.endswith(".htm") and not dst.endswith(".html"):
        dst += "/index.html"
    redirs.append((src, dst))
    logger.debug(f"Redirect: `{src}` -> `{dst}`")


def on_post_build(config: Dict[str, Any], **kwargs) -> None:
    if not enabled:
        return
    site_dir = config["site_dir"]
    template_file_path = os.path.join(site_dir, "redirection.html")
    with open(template_file_path, "r", encoding="utf-8") as f:
        template = f.read()
    for src, dst in redirs:
        if os.path.exists(os.path.join(site_dir, src[1:])):
            logger.warning(
                f"Skip creating redirection file `{src}` because it already exists"
            )
            continue
        if not os.path.exists(os.path.join(site_dir, dst[1:])):
            logger.warning(
                f"Skip creating redirection file `{src}` because the dest `{dst}` does not exist"
            )
            continue
        logger.debug(f"Creating redirection file `{src}` -> `{dst}`")
        src_file = re.sub(
            r"\./",
            "../" * src.count("/"),
            template,
        )
        src_file = re.sub(
            r"//old//",
            src.replace("index.html", ""),
            src_file,
        )
        src_file = re.sub(
            r"//new//",
            dst.replace("index.html", ""),
            src_file,
        )
        src_file = re.sub(
            r"//wait_time//",
            str(WAIT_TIME),
            src_file,
        )
        if WAIT_TIME == 0:
            src_file = re.sub(
                "<script>",
                f"<script>window.location='{dst.replace('index.html', '')}';",
                src_file,
            )
        os.makedirs(os.path.dirname(os.path.join(site_dir, src[1:])), exist_ok=True)
        with open(os.path.join(site_dir, src[1:]), "w", encoding="utf-8") as f:
            f.write(src_file)
