import re


def replace_standalone_words(word: str, target: str, string: str) -> str:
    return re.sub(f"\\b{word}\\b", target, string)


def replace_indented_block_start_with_options(target, handle, string):
    return re.sub(
        rf"(?P<leading>[ \t]*?)({target}(\[(?P<options>.*)\])?(\\zoom{{(?P<zoom>.*)}})?.*\n(?P<contents>(((?P=leading)(\t|(    )).*)|\n)*))",
        handle,
        string,
    )


def get_indentation_level(str):
    return (len(str) - len(str.lstrip())) // 4


def _set_line_indentation_level(line, level):
    prev_level = get_indentation_level(line)
    return (" " * 4 * (prev_level + level)) + line.lstrip()


def return_to_indentation_level(str, level):
    lines = str.split("\n")
    return "\n".join([_set_line_indentation_level(line, level) for line in lines])
