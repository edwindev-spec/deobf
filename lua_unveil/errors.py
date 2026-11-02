"""Exception hierarchy for Lua Unveil."""


class LuaUnveilError(Exception):
    """Base class for expected application errors."""


class LoadError(LuaUnveilError):
    """Raised when an input file cannot be loaded safely."""


class LexError(LuaUnveilError):
    """Raised when source text contains an unterminated lexical construct."""


class ParseError(LuaUnveilError):
    """Raised when structural Lua delimiters are unbalanced."""


class DeobfuscationError(LuaUnveilError):
    """Raised when a requested transformation cannot be completed."""


class VMError(LuaUnveilError):
    """Raised for malformed or invalid virtual-machine bytecode."""
