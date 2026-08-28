"""
Router selection tests.

Importing main registers the security commands into panda.router, then we
assert which command router.select() picks for a query — without running
any handler (no prompts). These lock in correct routing and the
word-boundary matching that prevents substring collisions.
"""
import main  # noqa: F401  (import registers the security commands)
from panda import router


def name_for(query):
    cmd = router.select(query)
    return cmd.name if cmd else None


def test_basic_routing():
    assert name_for("open the vault") == "vault"
    assert name_for("change my password") == "change"
    assert name_for("set the password") == "set"
    assert name_for("help") == "help"


def test_word_boundary_prevents_substring_collisions():
    # 'set' must not fire on 'sunset', 'reset', etc.
    assert name_for("watching the sunset") is None
    assert router.matches("set", "sunset") is False
    # But the real command word still routes.
    assert name_for("set my password") == "set"


def test_unknown_query_has_no_match():
    assert name_for("photosynthesis in plants") is None
    assert name_for("") is None


def test_matches_is_case_insensitive_and_whole_word():
    assert router.matches("vault", "OPEN THE VAULT") is True
    assert router.matches("change", "changelog") is False
