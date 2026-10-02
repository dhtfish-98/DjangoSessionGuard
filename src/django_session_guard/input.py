"""Local snapshots and bounded syntactic parsers. No input is executed."""
import ast
import hashlib
import io
import json
import os
import stat
import tokenize
import warnings
from .contracts import ReviewError

def read_local(path, limits):
    if not isinstance(path, (str, os.PathLike)):
        raise ReviewError("local_path_required")
    name = os.fspath(path)
    if not isinstance(name, str) or not name or name == "-" or "://" in name or "\x00" in name:
        raise ReviewError("local_path_required")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ReviewError("nofollow_unavailable")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ReviewError("regular_file_required")
            if before.st_size > limits.file_bytes:
                raise ReviewError("file_budget")
            raw = stream.read(limits.file_bytes + 1)
            after = os.fstat(stream.fileno())
            if len(raw) > limits.file_bytes:
                raise ReviewError("file_budget")
            if (not stat.S_ISREG(after.st_mode) or len(raw) != after.st_size or
                    (before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns)):
                raise ReviewError("input_changed")
    except (OSError, ValueError):
        raise ReviewError("local_read_error") from None
    try:
        source = raw.decode("utf-8")
    except UnicodeError:
        raise ReviewError("utf8_required") from None
    return source, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def location(node, line_starts):
    line, column = getattr(node, "lineno", 1), getattr(node, "col_offset", 0)
    return {"line": line, "byte_column": column, "byte_offset": line_starts[line - 1] + column}

def parse_python(source, limits):
    # AST parsing and compilation can issue warnings containing source text.
    # Record them inside this boundary and expose only a fixed code/location.
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        tree, starts = _parse_python(source, limits)
    if recorded:
        line = recorded[0].lineno
        loc = {"line": line} if type(line) is int and line > 0 else None
        raise ReviewError("python_compile_warning", loc)
    return tree, starts

def _parse_python(source, limits):
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source.encode("utf-8")).readline)
        if encoding.lower().replace("_", "-") not in ("utf-8", "utf8"):
            raise ReviewError("python_encoding_unsupported")
        if "\r" in source.replace("\r\n", ""):
            raise ReviewError("python_newline_unsupported")
        normalized = source.replace("\r\n", "\n")
        count, depth = 0, 0
        for token in tokenize.generate_tokens(io.StringIO(normalized).readline):
            count += 1
            if count > limits.tokens or len(token.string.encode("utf-8")) > limits.token_bytes:
                raise ReviewError("token_budget", {"line": token.start[0]})
            if token.type == tokenize.OP:
                if token.string in "([{":
                    depth += 1
                    if depth > limits.depth:
                        raise ReviewError("syntax_depth_budget", {"line": token.start[0]})
                elif token.string in ")]}":
                    depth -= 1
        tree = ast.parse(normalized, mode="exec")
    except SyntaxError as error:
        loc = {"line": error.lineno} if type(error.lineno) is int and error.lineno > 0 else None
        raise ReviewError("python_syntax_error", loc) from None
    except tokenize.TokenError as error:
        position = error.args[1] if len(error.args) > 1 else None
        loc = {"line": position[0]} if type(position) is tuple and type(position[0]) is int else None
        raise ReviewError("python_syntax_error", loc) from None
    except (UnicodeError, LookupError):
        raise ReviewError("python_encoding_unsupported") from None
    except (RecursionError, MemoryError):
        raise ReviewError("syntax_resource_error") from None
    pending, count = [(tree, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > limits.nodes or depth > limits.depth:
            raise ReviewError("ast_budget")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    try:
        # ast.parse accepts invalid control-flow declarations in dead branches.
        # Compile the bounded whole AST only for semantic validation; discard
        # the code object immediately, never execute or import it.
        compile(tree, "<DjangoSessionGuard input>", "exec", dont_inherit=True)
    except SyntaxError as error:
        loc = {"line": error.lineno} if type(error.lineno) is int and error.lineno > 0 else None
        raise ReviewError("python_semantic_error", loc) from None
    except (RecursionError, MemoryError):
        raise ReviewError("syntax_resource_error") from None
    starts, offset = [], 0
    # splitlines() also splits Unicode characters inside literals, unlike Python.
    for line in source.split("\n"):
        starts.append(offset)
        offset += len(line.encode("utf-8")) + 1
    return tree, starts or [0]

def parse_json(source, limits):
    # A string-aware bracket pass bounds nesting before the stdlib decoder.
    depth, quoted, escaped = 0, False, False
    for char in source:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limits.depth:
                raise ReviewError("json_depth_budget")
        elif char in "]}":
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ReviewError("json_duplicate_key")
            result[key] = value
        return result
    def reject_number(_):
        raise ReviewError("json_number_unsupported")
    try:
        result = json.loads(source, object_pairs_hook=pairs, parse_float=reject_number,
                            parse_constant=reject_number)
    except json.JSONDecodeError as error:
        raise ReviewError("json_syntax_error", {"line": error.lineno,
            "byte_offset": len(source[:error.pos].encode("utf-8"))}) from None
    except (ValueError, RecursionError, MemoryError):
        raise ReviewError("json_syntax_error") from None
    pending, count = [result], 0
    while pending:
        value = pending.pop()
        count += 1
        if count > limits.nodes:
            raise ReviewError("json_node_budget")
        if type(value) is dict:
            if len(value) > limits.items:
                raise ReviewError("item_budget")
            pending.extend(value.keys()); pending.extend(value.values())
        elif type(value) is list:
            if len(value) > limits.items:
                raise ReviewError("item_budget")
            pending.extend(value)
        elif type(value) is str:
            try:
                if len(value.encode("utf-8")) > limits.token_bytes:
                    raise ReviewError("token_budget")
            except UnicodeError:
                raise ReviewError("unicode_scalar_required") from None
        elif value is not None and type(value) not in (bool, int):
            raise ReviewError("json_value_unsupported")
    return result
