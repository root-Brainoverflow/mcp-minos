"""Static-analysis scanners.

Each scanner takes either a source-tree path or a list of tool definitions and
returns ``StaticFinding`` objects. They are pure (no side effects beyond
reading files / invoking the semgrep CLI) so the findings runner can compose
them freely.
"""
