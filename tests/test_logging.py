"""Test du logging structuré (item 8)."""

import logging

from core.context import Context


def test_ctx_log_emits_log_record(caplog):
    ctx = Context()
    with caplog.at_level(logging.INFO, logger="rto"):
        ctx.log("mon-module", "message de test")
    # Le message passe bien par le logger 'rto' (capturable / fichier / niveau).
    assert any("mon-module" in r.message and "message de test" in r.message
               for r in caplog.records)
    # Et il reste aussi dans la timeline (pour le rapport).
    assert ctx.timeline and ctx.timeline[-1]["module"] == "mon-module"


def test_setup_logging_configures_rto_logger():
    from main import setup_logging
    setup_logging(verbose=False, log_file=None)
    logger = logging.getLogger("rto")
    assert logger.level == logging.INFO
    assert logger.handlers           # au moins un handler (sortie standard)
