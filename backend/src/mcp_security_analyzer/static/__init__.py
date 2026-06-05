"""Static analyzer.

Produces an environment snapshot (``common.environment_snapshot``) plus a set
of static findings. The snapshot is consumed by the dynamic analyzer so that
runtime resolution and bootstrap planning can skip their own discovery.
"""
