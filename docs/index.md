# Welcome to MkDocs

For full documentation visit [mkdocs.org](https://www.mkdocs.org).

## Commands

* `mkdocs new [dir-name]` - Create a new project.
* `mkdocs serve` - Start the live-reloading docs server.
* `mkdocs build` - Build the documentation site.
* `mkdocs -h` - Print help message and exit.

## Project layout

```text
mkdocs.yml    # The configuration file.
docs/
    index.md  # The documentation homepage.
    ...       # Other markdown pages, images and other files.
```

=== "result"

    ```python title="example_scenes.py" linenums="12" hl_lines="4-6"
    class OpeningManimExample(Scene):
        def construct(self): # (1)
            intro_words = Text("""
                The original motivation for manim was to
                better illustrate mathematical functions
                as transformations.
            """)
    ```

    1. this is a function

    `#!python class Test(object):`

=== "markdown"

    <pre>
    &#96;&#96;&#96;python title="example_scenes.py" linenums="12" hl_lines="4-6"
    class OpeningManimExample(Scene):
        def construct(self): # (1)
            intro_words = Text("""
                The original motivation for manim was to
                better illustrate mathematical functions
                as transformations.
            """)
    &#96;&#96;&#96;

    1.&nbsp;this is a function

    &#96;#!python class Test(object):&#96;
    <pre/>

Text can be {--deleted--} and replacement text {++added++}. This can also be combined into {~~one~>a~~} single operation. {==Highlighting==} is also possible {>>and comments can be added inline<<}.

{==

Formatting can also be applied to blocks by putting the opening and closing tags on separate lines and adding new lines between the tags and the content.

==}

![Image title](https://dummyimage.com/300x200/eee/aaa){ align=left }

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla et euismod
nulla. Curabitur feugiat, tortor non consequat finibus, justo purus auctor
massa, nec semper lorem quam in massa.<br/><br/><br/><br/>

