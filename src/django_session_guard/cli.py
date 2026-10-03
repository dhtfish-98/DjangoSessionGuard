"""JSON-only stdout. Errors never interpolate input or filesystem paths."""
import argparse
from .review import review_settings, serialize

class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "DjangoSessionGuard: invalid_cli_arguments\n")

def main(argv=None):
    parser = SafeParser(description="Read-only static Django 5.2 session/CSRF settings review")
    parser.add_argument("path", help="explicit local regular UTF-8 file")
    parser.add_argument("--django-version", required=True, choices=("5.2",))
    parser.add_argument("--format", choices=("python", "json"), default="python")
    parser.add_argument("--version", action="version", version="DjangoSessionGuard 0.1.2")
    args = parser.parse_args(argv)
    report = review_settings(args.path, django_version=args.django_version, input_format=args.format)
    print(serialize(report))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
