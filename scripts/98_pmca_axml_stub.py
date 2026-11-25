"""Minimal stub for axmlparserpy.axmlprinter.AXMLPrinter.

Sony-PMCA-RE imports this at module load time for its APK commands, which we
never use (we only need serviceshell / firmware info).  The real package has a
heavy dependency chain that breaks on Python 3.14, so provide a stub that
raises only if actually used.
"""
import sys
import types


class AXMLPrinter(object):  # pragma: no cover - only a stub
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "axmlparserpy stub: APK parsing is not available in this setup"
        )


def _install():
    pkg = types.ModuleType("axmlparserpy")
    pkg.__path__ = []
    printer = types.ModuleType("axmlparserpy.axmlprinter")
    printer.AXMLPrinter = AXMLPrinter
    pkg.axmlprinter = printer
    sys.modules.setdefault("axmlparserpy", pkg)
    sys.modules.setdefault("axmlparserpy.axmlprinter", printer)


_install()
