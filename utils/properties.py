
from pathlib import Path

import yaml


SCHEMA_DIRECTORY = Path(__file__).resolve().parent.parent / "schemas"


def load_property_schema(filename: str) -> dict:
    schema_path = SCHEMA_DIRECTORY / filename

    if not schema_path.is_file():
        raise FileNotFoundError(f"Schema file not found: {filename}")

    with schema_path.open("r", encoding="utf-8") as file:
        schema = yaml.safe_load(file)

    if not isinstance(schema, dict):
        raise ValueError(f"{filename} must contain a YAML mapping")

    properties = schema.get("properties", schema)

    if not isinstance(properties, dict):
        raise ValueError(f"{filename} must define a properties mapping")

    return properties


def validate_properties(
    values: dict,
    schema: dict,
    partial: bool = False
) -> dict:
    if not isinstance(values, dict):
        raise ValueError("Properties must be an object")

    unknown = set(values) - set(schema)

    if unknown:
        raise ValueError(
            f"Unknown properties: {', '.join(sorted(unknown))}"
        )

    validated = {}

    for name, definition in schema.items():
        if isinstance(definition, str):
            definition = {"type": definition}

        if name not in values:
            if partial:
                continue

            if "default" in definition:
                validated[name] = definition["default"]
            elif definition.get("required", False):
                raise ValueError(f"Missing required property: {name}")

            continue

        value = values[name]
        expected_type = definition.get("type", "any")

        type_checks = {
            "string": lambda v: isinstance(v, str),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
            "array": lambda v: isinstance(v, list),
            "object": lambda v: isinstance(v, dict)
        }

        if expected_type in type_checks and not type_checks[expected_type](value):
            raise ValueError(
                f"{name} must be of type {expected_type}"
            )

        if "enum" in definition and value not in definition["enum"]:
            raise ValueError(
                f"{name} must be one of: {definition['enum']}"
            )

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in definition and value < definition["min"]:
                raise ValueError(f"{name} must be at least {definition['min']}")

            if "max" in definition and value > definition["max"]:
                raise ValueError(f"{name} must be at most {definition['max']}")

        if isinstance(value, (str, list, dict)):
            if "min_length" in definition and len(value) < definition["min_length"]:
                raise ValueError(f"{name} is too short")

            if "max_length" in definition and len(value) > definition["max_length"]:
                raise ValueError(f"{name} is too long")

        validated[name] = value

    return validated
