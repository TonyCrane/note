import os
from hashlib import sha256

from mkdocs.utils import log


class TeXError(BaseException):
    pass


class TeXWriterConfig:
    def __init__(self) -> None:
        self.compiler = "xelatex"
        self.preamble = ""


class TeXWriter:
    def __init__(self, config=TeXWriterConfig()) -> None:
        self.config = config

    def create_tex_file(self, content: str, tex_name: str) -> None:
        """
        Write content into tex_name, with preamble set by config
        """
        full_tex = (
            "\n\n".join(
                (self.config.preamble, "\\begin{document}", content, "\\end{document}")
            )
            + "\n"
        )

        try:
            with open(f"{tex_name}.tex", "w", encoding="utf-8") as tex_file:
                tex_file.write(full_tex)
        except OSError:
            log.error("[tikzautomata] unable to create tex file!")

    def create_svg_from_tex(self, tex_name: str) -> None:
        """
        Generate svg from tex file
        """
        if self.config.compiler == "xelatex":
            program = "xelatex -no-pdf"
        else:
            raise NotImplementedError(
                f"Compiler {self.config.compiler} is not implemented!"
            )

        log.info(f"rendering {tex_name}.svg")

        # use compiler to transform tex to pdf
        tex2xdv_cmd = " ".join(
            (
                program,
                "-halt-on-error",
                "-interaction=batchmode",
                f'"{tex_name}.tex"',
                ">",
                os.devnull,
            )
        )
        log.debug(f"running {tex2xdv_cmd}")
        if os.system(tex2xdv_cmd):
            log.error("LaTeX Error! Not a worry, it happens to the best of us.")
            raise TeXError("LaTeX Error! Look into log file for detail")

        # use dvisvgm to transform xdv to svg
        xdv2svg_cmd = " ".join(
            (
                "dvisvgm",
                f'"{tex_name}.xdv"',
                "-n",
                "-v 0",
                f'-o "{tex_name}.svg"',
                ">",
                os.devnull,
            )
        )
        log.debug(f"running {xdv2svg_cmd}")
        if os.system(xdv2svg_cmd):
            log.error("dvisvgm Error!")
            raise TeXError("dvisvgm Error!")

        # clean up
        for ext in (".log", ".aux", ".xdv", ".tex"):
            try:
                os.remove(tex_name + ext)
            except FileNotFoundError:
                pass


class TikZAutomataRenderer:
    def __init__(self, options: str, contents: str) -> None:
        self.options = options
        self.contents = contents

    def write_to_svg(self, cachefile: bool) -> str:
        filename = sha256(
            self.contents.encode() + (self.options.encode() if self.options else b"")
        ).hexdigest()

        if cachefile:
            try:
                os.chdir("cache")
            except OSError:
                log.error("[tikzautomata] cache directory not found!")

        if cachefile and os.path.exists(f"{filename}.svg"):
            log.debug("[tikzautomata] load from existing file...")
            with open(f"{filename}.svg", "r", encoding="utf-8") as f:
                svg_str = f.read(None)
            os.chdir("..")
            return svg_str

        writer = TeXWriter()
        writer.config.preamble = r"""
\documentclass[dvisvgm]{standalone}
\usepackage{tikz}

\usetikzlibrary {arrows.meta,automata,positioning,shapes.geometric}
        """
        begin_command = (
            r"\begin{tikzpicture}[%s]" % self.options
            if self.options
            else r"\begin{tikzpicture}[->,>={Stealth[round]},shorten >=1pt,auto,node distance=2cm,on grid,semithick,inner sep=2pt,bend angle=50,initial text=]"
        )
        writer.create_tex_file(
            "\n".join(
                (
                    begin_command,
                    self.contents.strip(),
                    "\\end{tikzpicture}\n",
                )
            ),
            filename,
        )

        writer.create_svg_from_tex(filename)

        with open(f"{filename}.svg", "r", encoding="utf-8") as f:
            svg_str = f.read(None)

        # clean up
        if not cachefile:
            try:
                os.remove(filename + ".svg")
            except FileNotFoundError:
                pass

        os.chdir("..")

        return svg_str
