"""
AI Resolver Generator
======================
When SentinelShield detects a threat type with no built-in resolver, this module
uses the Claude API to synthesise a new BaseResolver subclass on-the-fly, registers
it in RESOLVER_MAP, and persists the generated code to the database for audit.
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

import anthropic

from config import settings
from database import SessionLocal, GeneratedResolver as GeneratedResolverModel

logger = logging.getLogger("sentinel.ai_resolver")

# ── Prompts ────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a Python security automation engineer writing resolver code for SentinelShield,
a real-time threat detection and response system.

A resolver is a Python class that executes automated remediation when a security
threat is detected.  You must write a single class that:

  • Inherits from BaseResolver (already imported into the execution namespace)
  • Has __init__ calling super().__init__("<DescriptiveName>") with a short human-readable name
  • Implements  async def resolve(self, metadata: dict) -> ResolutionResult
  • Uses ONLY the names already available in scope:
      BaseResolver, ResolutionResult, datetime, timezone, time, logging, logger
  • Performs LOGICAL, IN-MEMORY remediation — update tracking dicts, derive
    response context, and return a populated ResolutionResult

ResolutionResult fields:
  action_type        : str   – e.g. "block_sql_injection"
  status             : str   – "success" | "failed" | "partial"
  details            : dict  – operator-readable context (ip, pattern, duration, human action string, …)
  rollback_available : bool
  timestamp          : datetime – use datetime.now(timezone.utc)

Rules:
  • Do NOT add any import statements.
  • Do NOT use subprocess, os, requests, socket, or file I/O.
  • Output ONLY the Python class definition — no markdown fences, no comments
    outside the class, no explanatory text.
"""

_USER_TEMPLATE = """\
A new security threat with no existing resolver has been detected.
Generate a resolver class named exactly `{class_name}` to handle it.

Threat Type      : {alert_type}
Severity         : {severity}
Title            : {title}
Description      : {description}
Affected Resource: {affected_resource}
Detection Method : {detection_method}
Risk Score       : {risk_score}/100
Metadata         : {metadata}
Resolver Action  : {resolver_action}

Write `{class_name}` now.
"""

# ── Helpers ────────────────────────────────────────────────────────────────────

def _to_class_name(action_type: str) -> str:
    """Convert 'sql_injection_block' → 'SqlInjectionBlockResolver'."""
    return "".join(w.capitalize() for w in action_type.split("_")) + "Resolver"


def _strip_markdown(code: str) -> str:
    """Remove ```python / ``` fences if the model adds them despite instructions."""
    lines = code.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)


# ── Core generator ─────────────────────────────────────────────────────────────

async def generate_and_register(
    resolver_action: str,
    detection_context: dict,
    metadata: dict,
) -> Optional[object]:
    """
    Ask Claude to write a new BaseResolver subclass for *resolver_action*,
    exec() it safely, persist the code, and return the live instance.

    Returns the resolver instance on success, None on any failure.
    """
    if not settings.anthropic_api_key:
        logger.error(
            "ANTHROPIC_API_KEY is not set — cannot auto-generate resolver for '%s'",
            resolver_action,
        )
        return None

    class_name = _to_class_name(resolver_action)
    logger.info("🤖 No resolver found for '%s' — invoking Claude to generate '%s'…",
                resolver_action, class_name)

    user_message = _USER_TEMPLATE.format(
        class_name=class_name,
        alert_type=detection_context.get("alert_type", "unknown"),
        severity=detection_context.get("severity", "unknown"),
        title=detection_context.get("title", ""),
        description=detection_context.get("description", ""),
        affected_resource=detection_context.get("affected_resource", {}),
        detection_method=detection_context.get("detection_method", ""),
        risk_score=detection_context.get("risk_score", 0),
        metadata=metadata,
        resolver_action=resolver_action,
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_code = response.content[0].text
    except Exception as exc:
        logger.error("Claude API call failed: %s", exc)
        return None

    generated_code = _strip_markdown(raw_code)
    logger.debug("Generated resolver code:\n%s", generated_code)

    # ── Execute in a controlled namespace ─────────────────────────────────────
    from resolvers.resolvers import BaseResolver, ResolutionResult  # local import avoids circular ref

    namespace = {
        "BaseResolver": BaseResolver,
        "ResolutionResult": ResolutionResult,
        "datetime": datetime,
        "timezone": timezone,
        "time": time,
        "logging": logging,
        "logger": logging.getLogger(f"sentinel.resolver.ai.{resolver_action}"),
    }

    try:
        exec(generated_code, namespace)  # noqa: S102
    except Exception as exc:
        logger.error("exec() of generated resolver failed: %s\nCode:\n%s", exc, generated_code)
        return None

    resolver_class = namespace.get(class_name)
    if resolver_class is None:
        logger.error(
            "Generated code did not define a class named '%s'. Got keys: %s",
            class_name, [k for k in namespace if not k.startswith("_")],
        )
        return None

    try:
        instance = resolver_class()
    except Exception as exc:
        logger.error("Could not instantiate '%s': %s", class_name, exc)
        return None

    logger.info("✅ AI-generated resolver '%s' instantiated successfully", class_name)

    # ── Persist to database ───────────────────────────────────────────────────
    _persist(resolver_action, detection_context.get("alert_type", "unknown"),
             generated_code, user_message)

    return instance


def _persist(action_type: str, threat_type: str, code: str, prompt: str) -> None:
    """Write the generated resolver record to the database (best-effort)."""
    db = SessionLocal()
    try:
        record = GeneratedResolverModel(
            id=uuid.uuid4(),
            action_type=action_type,
            threat_type=threat_type,
            code=code,
            status="active",
            generation_prompt=prompt,
        )
        db.add(record)
        db.commit()
        logger.info("Persisted generated resolver '%s' to database", action_type)
    except Exception as exc:
        logger.error("Failed to persist generated resolver: %s", exc)
    finally:
        db.close()
