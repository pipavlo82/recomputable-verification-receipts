# Bounded end-anchor compatibility analysis

The first repair attempt used Python re.search without other interpretation changes.
The preserved full-CLI witness `^abc$` / `abc\n` changed from rejection to
acceptance in Python; JavaScript RegExp without flags rejected it. This was a
new regression, not a successful correction. Attempt-one source and results
remain in the external evidence package.

The final candidate rewrites an unescaped `$` outside a character class to
Python `\Z` before compiling, implementing absolute end-of-input for the
no-flags interface. It preserves escaped dollar signs, character-class dollars,
and alternatives. It does not rewrite pinned schema bytes or their digest.
Public CLI controls cover final LF, escaped dollar, character-class dollar,
alternative branch, and an unanchored match before a final LF.

This does not introduce a new regex engine or claim full ECMA-262 support.
Existing Python inline flags, escapes, character classes and Unicode behavior
can still differ from ECMAScript. In particular `^.$` on an astral scalar and
`\d` on an Arabic-Indic digit remain explicit incompatible cases. This helper
is a bounded local repair candidate, not a general regex transpiler.

Publication remains HOLD pending a supported-pattern/capability policy and
adapter release/version decision. No profile contract is weakened to accommodate
these implementation limits. Replacing the engine or widening the supported
grammar requires a separate compatibility analysis.
