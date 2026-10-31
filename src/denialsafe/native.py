"""Actual Cedar and Balana common-fragment adapters, with retained raw decisions."""

import json
import re
import subprocess
import uuid
from pathlib import Path
import xml.etree.ElementTree as ET

CATEGORY = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
FUNCTION = "urn:oasis:names:tc:xacml:1.0:function:"
TYPE = "http://www.w3.org/2001/XMLSchema#"


def native_type(value):
    if type(value) is bool:
        return "boolean"
    if type(value) is int and -(2**63) <= value < 2**63:
        return "integer"
    if type(value) is str:
        return "string"
    raise ValueError(
        "Native common fragment supports Boolean, signed-64 integer and string attributes"
    )


def fragment(policy, request):
    if set(policy) - {"required", "equals", "members", "minimum", "maximum", "denies"}:
        raise ValueError("Unsupported native policy construct")
    fields = (
        set(policy.get("required", []))
        | set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
        | set(policy.get("maximum", {}))
        | {name for rule in policy.get("denies", []) for name in rule}
    )
    if fields - set(request):
        raise ValueError(
            "Missing common-fragment attribute; native category support not assumed"
        )
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) for name in fields):
        raise ValueError("Unsupported attribute name")
    types = {name: native_type(request[name]) for name in fields}
    for name, value in policy.get("equals", {}).items():
        if native_type(value) != types[name]:
            raise ValueError("Ill-typed native equality")
    for name, values in policy.get("members", {}).items():
        if any(native_type(value) != types[name] for value in values):
            raise ValueError("Ill-typed native membership")
    for kind in ("minimum", "maximum"):
        for name, value in policy.get(kind, {}).items():
            if types[name] != "integer" or native_type(value) != "integer":
                raise ValueError("Native numeric fragment requires integers")
    for clause in policy.get("denies", []):
        for name, value in clause.items():
            if native_type(value) != types[name]:
                raise ValueError("Ill-typed native deny predicate")
    return fields, types


def cedar_source(policy, request):
    fields, types = fragment(policy, request)

    def literal(value):
        native_type(value)
        return json.dumps(value, ensure_ascii=True)

    conditions = ["context has " + name for name in sorted(fields)]
    conditions += [
        "context." + name + " == " + literal(value)
        for name, value in policy.get("equals", {}).items()
    ]
    conditions += [
        "["
        + ",".join(literal(value) for value in values)
        + "].contains(context."
        + name
        + ")"
        for name, values in policy.get("members", {}).items()
    ]
    for key, op in (("minimum", ">="), ("maximum", "<=")):
        conditions += [
            "context." + name + " " + op + " " + literal(value)
            for name, value in policy.get(key, {}).items()
        ]
    lines = [
        "permit(principal, action, resource) when { "
        + (" && ".join(conditions) or "true")
        + " };"
    ]
    for clause in policy.get("denies", []):
        lines.append(
            "forbid(principal, action, resource) when { "
            + (
                " && ".join(
                    "context has "
                    + name
                    + " && context."
                    + name
                    + " == "
                    + literal(value)
                    for name, value in clause.items()
                )
                or "true"
            )
            + " };"
        )
    query = dict(
        principal="User::" + json.dumps(str(request.get("principal", "subject"))),
        action='Action::"read"',
        resource='Resource::"protected"',
        context=request,
    )
    return "\n".join(lines), query


def cedar(policy, request, executable, output, timeout=30):
    root = Path(output) / uuid.uuid4().hex
    root.mkdir(parents=True)
    text, query = cedar_source(policy, request)
    paths = [root / name for name in ("policy.cedar", "request.json", "entities.json")]
    for path, value in zip(paths, (text, json.dumps(query), "[]")):
        path.write_text(value, encoding="utf-8")
    result = subprocess.run(
        [
            str(executable),
            "authorize",
            "--policies",
            str(paths[0]),
            "--request-json",
            str(paths[1]),
            "--entities",
            str(paths[2]),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    (root / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (root / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode not in (0, 2):
        raise RuntimeError("Cedar failed: " + result.stderr)
    raw = (
        "Allow"
        if re.search(r"\bALLOW\b", result.stdout)
        else "Deny"
        if re.search(r"\bDENY\b", result.stdout)
        else None
    )
    if raw is None:
        raise RuntimeError("Cedar returned no decision")
    return dict(
        decision="Permit" if raw == "Allow" else "Deny",
        native_decision=raw,
        published_projection="Cedar Allow->Permit, Deny->Deny over typed total common fragment",
        artifacts=str(root),
    )


def xacml_source(policy, request):
    fields, types = fragment(policy, request)

    def element(tag, **attrs):
        return ET.Element(tag, attrs)

    def literal(value):
        item = element("AttributeValue", DataType=TYPE + native_type(value))
        item.text = str(value).lower() if type(value) is bool else str(value)
        return item

    def reference(name):
        designator = element(
            "AttributeDesignator",
            AttributeId="urn:denialsafe:" + name,
            Category=CATEGORY,
            DataType=TYPE + types[name],
            MustBePresent="true",
        )
        one = element("Apply", FunctionId=FUNCTION + types[name] + "-one-and-only")
        one.append(designator)
        return one

    def apply(operation, *args):
        item = element("Apply", FunctionId=FUNCTION + operation)
        item.extend(args)
        return item

    def test(name, operation, value):
        return apply(types[name] + "-" + operation, reference(name), literal(value))

    checks = [
        test(name, "equal", value) for name, value in policy.get("equals", {}).items()
    ]
    checks += [
        apply("or", *(test(name, "equal", value) for value in values))
        if values
        else literal(False)
        for name, values in policy.get("members", {}).items()
    ]
    for kind, operation in (
        ("minimum", "greater-than-or-equal"),
        ("maximum", "less-than-or-equal"),
    ):
        checks += [
            test(name, operation, value) for name, value in policy.get(kind, {}).items()
        ]
    # Touch explicitly required attributes, preserving MustBePresent errors.
    checks += [
        apply(types[name] + "-equal", reference(name), reference(name))
        for name in policy.get("required", [])
        if name
        not in set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
        | set(policy.get("maximum", {}))
    ]
    root = element(
        "Policy",
        xmlns=NS,
        PolicyId="urn:denialsafe:common",
        Version="1.0",
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides",
    )
    root.append(element("Target"))
    for index, clause in enumerate(policy.get("denies", [])):
        rule = element("Rule", RuleId="deny" + str(index), Effect="Deny")
        condition = element("Condition")
        terms = [test(name, "equal", value) for name, value in clause.items()]
        condition.append(apply("and", *terms) if terms else literal(True))
        rule.append(condition)
        root.append(rule)
    rule = element("Rule", RuleId="allow", Effect="Permit")
    condition = element("Condition")
    condition.append(apply("and", *checks) if checks else literal(True))
    rule.append(condition)
    root.append(rule)
    call = element(
        "Request", xmlns=NS, ReturnPolicyIdList="false", CombinedDecision="false"
    )
    attributes = element("Attributes", Category=CATEGORY)
    for name in sorted(fields):
        attribute = element(
            "Attribute", AttributeId="urn:denialsafe:" + name, IncludeInResult="false"
        )
        attribute.append(literal(request[name]))
        attributes.append(attribute)
    call.append(attributes)
    return ET.tostring(root, encoding="unicode"), ET.tostring(call, encoding="unicode")


def balana(policy, request, java, classpath, output, timeout=30):
    root = Path(output) / uuid.uuid4().hex
    policies = root / "policies"
    policies.mkdir(parents=True)
    text, query = xacml_source(policy, request)
    (policies / "policy.xml").write_text(text, encoding="utf-8")
    (root / "request.xml").write_text(query, encoding="utf-8")
    result = subprocess.run(
        [
            str(java),
            "-Dfile.encoding=UTF-8",
            "-cp",
            str(classpath),
            "org.denialsafe.BalanaBridge",
            str(policies.resolve()),
            str((root / "request.xml").resolve()),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    (root / "stdout.xml").write_text(result.stdout, encoding="utf-8")
    (root / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError("Balana failed: " + result.stderr)
    response = ET.fromstring(result.stdout.strip())
    decisions = [
        item.text
        for item in response.iter()
        if item.tag.rsplit("}", 1)[-1] == "Decision"
    ]
    if len(decisions) != 1:
        raise RuntimeError("Balana response requires one decision")
    raw = decisions[0]
    return dict(
        decision="Deny" if raw == "NotApplicable" else raw,
        native_decision=raw,
        published_projection="total-conjunctive policy maps NotApplicable->Deny; Indeterminate retained",
        artifacts=str(root),
    )
