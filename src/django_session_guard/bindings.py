"""A small static interpreter; mutable sequence aliases follow Python binding order."""
import ast
from dataclasses import dataclass
from .contracts import DEFAULTS, ReviewError
from .input import location

@dataclass
class Value:
    kind: str
    data: object = None

UNKNOWN = Value("unknown")

def box(value):
    if type(value) in (list, tuple):
        return Value(type(value).__name__, [box(item) for item in value])
    return Value(type(value).__name__, value)

class Binder:
    def __init__(self, limits, starts):
        self.limits, self.starts = limits, starts
        self.env, self.locations, self.diagnostics = {}, {}, []
        self.defaults_trusted, self.steps = True, 0
        self.effect_epoch = 0

    def tick(self):
        self.steps += 1
        if self.steps > self.limits.steps:
            raise ReviewError("model_step_budget")

    def issue(self, code, node):
        loc = location(node, self.starts)
        item = {"code": code, "location": loc}
        if item not in self.diagnostics:
            if len(self.diagnostics) >= self.limits.findings:
                raise ReviewError("finding_budget", loc)
            self.diagnostics.append(item)

    def barrier(self, code, node):
        self.issue(code, node)
        self.effect_epoch += 1
        self.defaults_trusted = False
        self.env = {name: UNKNOWN for name in self.env}

    def value(self, node):
        self.tick()
        if isinstance(node, ast.Constant) and type(node.value) in (str, bool, int, type(None)):
            if type(node.value) is str:
                try:
                    width = len(node.value.encode("utf-8"))
                except UnicodeError:
                    raise ReviewError("unicode_scalar_required", location(node, self.starts)) from None
                if width > self.limits.token_bytes:
                    raise ReviewError("value_budget", location(node, self.starts))
            return box(node.value)
        if isinstance(node, ast.Name):
            return self.env.get(node.id, UNKNOWN)
        if isinstance(node, (ast.List, ast.Tuple)):
            items = []
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    expanded = self.value(item.value)
                    if expanded.kind in ("list", "tuple"):
                        items.extend(expanded.data)
                    else:
                        if expanded.kind == "unknown":
                            self.barrier("unknown_iteration_effects", item)
                        return UNKNOWN
                else:
                    items.append(self.value(item))
                if len(items) > self.limits.items:
                    raise ReviewError("item_budget", location(node, self.starts))
            return Value("list" if isinstance(node, ast.List) else "tuple", items)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.value(node.left), self.value(node.right)
            if "unknown" in (left.kind, right.kind):
                self.barrier("unknown_operator_effects", node)
                return UNKNOWN
            if left.kind == right.kind and left.kind in ("str", "list", "tuple"):
                combined = left.data + right.data
                ceiling = self.limits.token_bytes if left.kind == "str" else self.limits.items
                size = len(combined.encode("utf-8")) if left.kind == "str" else len(combined)
                if size > ceiling:
                    raise ReviewError("value_budget", location(node, self.starts))
                return Value(left.kind, combined)
            return UNKNOWN
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.value(node.operand)
            if value.kind == "unknown":
                self.barrier("unknown_truth_effects", node)
                return UNKNOWN
            return box(not value.data) if value.kind == "bool" else UNKNOWN
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = self.value(node.operand)
            if value.kind == "unknown":
                self.barrier("unknown_operator_effects", node)
                return UNKNOWN
            if value.kind == "int":
                return box(value.data if isinstance(node.op, ast.UAdd) else -value.data)
            return UNKNOWN
        return UNKNOWN

    def executes_unknown(self, node):
        # Structural gate only: supported operators also need value-sensitive
        # checks in value(), because an unknown operand can call user code.
        allowed = (ast.Constant, ast.Name, ast.List, ast.Tuple, ast.Starred,
                   ast.BinOp, ast.Add, ast.UnaryOp, ast.Not, ast.UAdd, ast.USub, ast.Load)
        return any(not isinstance(child, allowed) for child in ast.walk(node))

    def assign(self, name, value, node):
        if name in ("SECRET_KEY", "SECRET_KEY_FALLBACKS"):
            return  # No secret analysis or binding is part of this profile.
        if name not in self.env and len(self.env) >= self.limits.bindings:
            raise ReviewError("binding_budget", location(node, self.starts))
        self.env[name] = value
        if name in DEFAULTS or name == "MIDDLEWARE_CLASSES":
            self.locations[name] = location(node, self.starts)

    def statements(self, statements):
        for node in statements:
            self.tick()
            if isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) for t in node.targets):
                if self.executes_unknown(node.value):
                    self.barrier("dynamic_expression", node)
                    value = UNKNOWN
                else:
                    epoch = self.effect_epoch
                    value = self.value(node.value)
                    # An inner callback may mutate containers already captured
                    # by this expression. Do not rebind a stale outer value.
                    if epoch != self.effect_epoch:
                        value = UNKNOWN
                    if value.kind == "unknown" or (value.kind in ("list", "tuple") and
                            any(item.kind == "unknown" for item in value.data)):
                        self.issue("unresolved_static_value", node)
                for target in node.targets:
                    self.assign(target.id, value, node)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                # Annotation evaluation can itself execute code or resolve dynamic names.
                self.barrier("annotation_unsupported", node)
                self.assign(node.target.id, UNKNOWN, node)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                if self.executes_unknown(node.value):
                    self.barrier("dynamic_expression", node)
                    continue
                epoch = self.effect_epoch
                left, right = self.env.get(node.target.id, UNKNOWN), self.value(node.value)
                if epoch != self.effect_epoch:
                    self.assign(node.target.id, UNKNOWN, node)
                    continue
                if left.kind == right.kind and left.kind in ("list", "tuple", "str"):
                    combined = left.data + right.data
                    size = len(combined.encode("utf-8")) if left.kind == "str" else len(combined)
                    if size > (self.limits.token_bytes if left.kind == "str" else self.limits.items):
                        raise ReviewError("value_budget", location(node, self.starts))
                    if left.kind == "list":
                        left.data[:] = combined
                        for name, bound in self.env.items():
                            if bound is left and name in DEFAULTS:
                                self.locations[name] = location(node, self.starts)
                        self.assign(node.target.id, left, node)
                    else:
                        self.assign(node.target.id, Value(left.kind, combined), node)
                else:
                    self.barrier("augmented_assignment_unsupported", node)
            elif isinstance(node, ast.If):
                if self.executes_unknown(node.test):
                    self.barrier("dynamic_condition", node)
                else:
                    condition = self.value(node.test)
                    if condition.kind == "bool":
                        self.statements(node.body if condition.data else node.orelse)
                    else:
                        self.barrier("unknown_branch", node)
            elif isinstance(node, ast.Pass) or (isinstance(node, ast.Expr) and
                    isinstance(node.value, ast.Constant) and type(node.value.value) is str):
                continue
            else:
                self.barrier("statement_unsupported", node)

    def projection(self):
        values = {name: self.env.get(name, box(default) if self.defaults_trusted else UNKNOWN)
                  for name, default in DEFAULTS.items()}
        if "MIDDLEWARE_CLASSES" in self.env:
            self.diagnostics.append({"code": "legacy_middleware_classes", "location": self.locations.get("MIDDLEWARE_CLASSES")})
        return values, self.locations, self.diagnostics

def bind_python(tree, starts, limits):
    binder = Binder(limits, starts)
    binder.statements(tree.body)
    return binder.projection()

def bind_json(document, limits):
    if type(document) is not dict or set(document) != {"schema_version", "django_version", "settings"}:
        raise ReviewError("projection_schema")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ReviewError("projection_schema")
    if document["django_version"] != "5.2" or type(document["settings"]) is not dict:
        raise ReviewError("projection_profile")
    settings = document["settings"]
    locations = {name: {"json_pointer": "/settings/" + name} for name in DEFAULTS if name in settings}
    diagnostics = []
    if any(name not in DEFAULTS for name in settings):
        diagnostics.append({"code": "projection_unknown_setting", "location": {"json_pointer": "/settings"}})
    return ({name: box(settings.get(name, default)) for name, default in DEFAULTS.items()},
            locations, diagnostics)
