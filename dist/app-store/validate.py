#!/usr/bin/env python3
"""Validate the canonical iOS App Store metadata and screenshot package."""

import argparse
import re
import struct
import sys
from pathlib import Path
from urllib.parse import urlsplit


STORE_ROOT = Path(__file__).resolve().parent
METADATA_ROOT = STORE_ROOT / "metadata" / "en-US"
SCREENSHOT_ROOT = STORE_ROOT / "screenshots" / "en-US"

EXPECTED_VERSION = "0.5.0"
EXPECTED_BUILD = "41"

# Apple counts keywords and review notes in UTF-8 bytes; the other text limits
# below are characters.
FIELD_RULES = {
    "name.txt": (2, 30, "characters"),
    "subtitle.txt": (0, 30, "characters"),
    "promotional-text.txt": (0, 170, "characters"),
    "description.txt": (1, 4000, "characters"),
    "keywords.txt": (1, 100, "bytes"),
    "copyright.txt": (1, 200, "characters"),
    "review-notes.txt": (1, 4000, "bytes"),
    "whats-new.txt": (0, 4000, "characters"),
    "support-url.txt": (1, None, "characters"),
    "marketing-url.txt": (0, None, "characters"),
    "privacy-policy-url.txt": (1, None, "characters"),
}

PUBLIC_PLAIN_TEXT_FIELDS = {
    "name.txt",
    "subtitle.txt",
    "promotional-text.txt",
    "description.txt",
}

URL_FIELDS = {
    "support-url.txt": True,
    "marketing-url.txt": False,
    "privacy-policy-url.txt": True,
}

# Current App Store Connect iPhone screenshot sizes. A single localization should
# use one physical resolution throughout, although portrait and landscape may be
# mixed for that resolution.
IPHONE_SCREENSHOT_SIZES = {
    (1260, 2736): "6.9-inch",
    (1290, 2796): "6.9-inch",
    (1320, 2868): "6.9-inch",
    (1242, 2688): "6.5-inch",
    (1284, 2778): "6.5-inch",
}

SCREENSHOT_NAME = re.compile(r"^[0-9]{2}-[a-z0-9][a-z0-9-]*\.(?:png|jpe?g)$")
HTML_TAG = re.compile(r"<[^>]+>")
COPYRIGHT = re.compile(r"^[0-9]{4} .+")
JPEG_SOF_MARKERS = {
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
}


class Validation:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, message):
        self.errors.append(message)

    def warn(self, message):
        self.warnings.append(message)


def read_text_field(path, validation):
    try:
        raw = path.read_bytes()
    except OSError as error:
        validation.error("{}: cannot read: {}".format(path, error))
        return ""

    if raw.startswith(b"\xef\xbb\xbf"):
        validation.error("{}: UTF-8 BOM is not allowed".format(path))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        validation.error("{}: invalid UTF-8: {}".format(path, error))
        return ""

    if "\r" in text:
        validation.error("{}: use LF line endings".format(path))
    if not text.endswith("\n"):
        validation.error("{}: file must end with exactly one newline".format(path))
        value = text
    else:
        value = text[:-1]
        if value.endswith("\n"):
            validation.error("{}: file has more than one trailing newline".format(path))

    for line_number, line in enumerate(value.split("\n"), start=1):
        if line.endswith((" ", "\t")):
            validation.error(
                "{}:{}: trailing whitespace is not allowed".format(path, line_number)
            )
    for character in value:
        if ord(character) < 32 and character not in {"\n", "\t"}:
            validation.error("{}: contains a control character".format(path))
            break
    return value


def validate_url(filename, value, required, validation):
    if not value and not required:
        return
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        validation.error("{}: must be an absolute HTTPS URL".format(filename))
    if parsed.username or parsed.password:
        validation.error("{}: URL credentials are not allowed".format(filename))
    if "\n" in value or "\t" in value or " " in value:
        validation.error("{}: URL contains whitespace".format(filename))


def validate_metadata(validation):
    values = {}
    for filename, (minimum, maximum, unit) in FIELD_RULES.items():
        path = METADATA_ROOT / filename
        if not path.is_file():
            validation.error("{}: required metadata file is missing".format(path))
            continue
        value = read_text_field(path, validation)
        values[filename] = value
        length = len(value.encode("utf-8")) if unit == "bytes" else len(value)
        if length < minimum:
            validation.error(
                "{}: {} {} is below the minimum of {}".format(
                    filename, length, unit, minimum
                )
            )
        if maximum is not None and length > maximum:
            validation.error(
                "{}: {} {} exceeds the limit of {}".format(
                    filename, length, unit, maximum
                )
            )

    for filename in PUBLIC_PLAIN_TEXT_FIELDS:
        value = values.get(filename, "")
        if "`" in value:
            validation.error(
                "{}: backticks render literally in App Store plain text".format(filename)
            )
        if HTML_TAG.search(value):
            validation.error("{}: HTML is not supported".format(filename))

    for filename, required in URL_FIELDS.items():
        validate_url(filename, values.get(filename, ""), required, validation)

    keywords = values.get("keywords.txt", "")
    keyword_items = keywords.split(",") if keywords else []
    if any(item != item.strip() for item in keyword_items):
        validation.error("keywords.txt: do not put spaces around commas")
    normalized_keywords = [item.casefold() for item in keyword_items]
    if any(len(item) <= 2 for item in keyword_items):
        validation.error("keywords.txt: every keyword must exceed two characters")
    if len(normalized_keywords) != len(set(normalized_keywords)):
        validation.error("keywords.txt: duplicate keywords are not allowed")

    indexed_words = set(
        re.findall(
            r"[a-z0-9]+",
            "{} {} Denuo Web".format(
                values.get("name.txt", ""), values.get("subtitle.txt", "")
            ).casefold(),
        )
    )
    duplicates = sorted(
        item for item in normalized_keywords if item in indexed_words
    )
    if duplicates:
        validation.error(
            "keywords.txt: duplicates already-indexed name/subtitle/company terms: {}".format(
                ", ".join(duplicates)
            )
        )

    copyright_value = values.get("copyright.txt", "")
    if copyright_value and not COPYRIGHT.fullmatch(copyright_value):
        validation.error(
            "copyright.txt: expected a four-digit year followed by the rights holder"
        )

    privacy_url = values.get("privacy-policy-url.txt", "")
    support_url = values.get("support-url.txt", "")
    review_notes = values.get("review-notes.txt", "")
    for label, canonical_url in (
        ("privacy", privacy_url),
        ("support", support_url),
    ):
        if canonical_url and canonical_url not in review_notes:
            validation.error(
                "review-notes.txt: must include the canonical {} URL".format(label)
            )

    readme_path = STORE_ROOT / "metadata" / "README.md"
    if not readme_path.is_file():
        validation.error("{}: package README is missing".format(readme_path))
    else:
        readme = read_text_field(readme_path, validation)
        for marker in (
            "- Version: `{}`".format(EXPECTED_VERSION),
            "- Build: `{}`".format(EXPECTED_BUILD),
        ):
            if marker not in readme:
                validation.error(
                    "{}: missing canonical marker {}".format(readme_path, marker)
                )

    checklist_path = STORE_ROOT / "submission-checklist.md"
    if not checklist_path.is_file():
        validation.error("{}: submission checklist is missing".format(checklist_path))
    else:
        read_text_field(checklist_path, validation)

    if values.get("whats-new.txt", ""):
        validation.warn(
            "whats-new.txt is a future-update draft; do not enter it for version 0.5.0"
        )
    return values


def png_info(path):
    data = path.read_bytes()
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("invalid PNG signature or truncated IHDR")
    if data[12:16] != b"IHDR":
        raise ValueError("PNG does not start with IHDR")
    width, height = struct.unpack(">II", data[16:24])
    color_type = data[25]
    has_alpha = color_type in {4, 6}

    offset = 8
    while offset + 12 <= len(data):
        chunk_length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + chunk_length
        if chunk_end > len(data):
            raise ValueError("truncated PNG chunk")
        if chunk_type == b"tRNS":
            has_alpha = True
        offset = chunk_end
        if chunk_type == b"IEND":
            break
    return width, height, has_alpha


def jpeg_info(path):
    data = path.read_bytes()
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise ValueError("invalid JPEG signature")
    offset = 2
    while offset < len(data):
        while offset < len(data) and data[offset] != 0xFF:
            offset += 1
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in {0x01, 0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(data):
            break
        segment_length = struct.unpack(">H", data[offset : offset + 2])[0]
        if segment_length < 2 or offset + segment_length > len(data):
            raise ValueError("invalid JPEG segment")
        if marker in JPEG_SOF_MARKERS:
            if segment_length < 7:
                raise ValueError("truncated JPEG SOF segment")
            height, width = struct.unpack(">HH", data[offset + 3 : offset + 7])
            return width, height, False
        offset += segment_length
    raise ValueError("JPEG dimensions were not found")


def image_info(path):
    if path.suffix.casefold() == ".png":
        return png_info(path)
    return jpeg_info(path)


def validate_screenshots(validation):
    if not SCREENSHOT_ROOT.is_dir():
        validation.error(
            "{}: screenshot directory is missing; add the final en-US screenshots".format(
                SCREENSHOT_ROOT
            )
        )
        return

    entries = sorted(path for path in SCREENSHOT_ROOT.iterdir() if not path.name.startswith("."))
    non_files = [path.name for path in entries if not path.is_file()]
    if non_files:
        validation.error(
            "{}: unexpected directories: {}".format(
                SCREENSHOT_ROOT, ", ".join(non_files)
            )
        )
    screenshots = [
        path
        for path in entries
        if path.is_file() and path.suffix.casefold() in {".png", ".jpg", ".jpeg"}
    ]
    unsupported = [path.name for path in entries if path.is_file() and path not in screenshots]
    if unsupported:
        validation.error(
            "{}: unsupported files: {}".format(
                SCREENSHOT_ROOT, ", ".join(unsupported)
            )
        )
    if not screenshots:
        validation.error("{}: at least one screenshot is required".format(SCREENSHOT_ROOT))
        return
    if len(screenshots) > 10:
        validation.error("{}: at most ten screenshots are allowed".format(SCREENSHOT_ROOT))

    sequence = [int(path.name[:2]) for path in screenshots if SCREENSHOT_NAME.fullmatch(path.name)]
    if sequence != list(range(1, len(screenshots) + 1)):
        validation.error(
            "{}: screenshot numbering must be contiguous from 01 in display order".format(
                SCREENSHOT_ROOT
            )
        )

    physical_sizes = set()
    display_classes = set()
    for path in screenshots:
        if not SCREENSHOT_NAME.fullmatch(path.name):
            validation.error(
                "{}: use a display-order name such as 01-handshake-page.png".format(path)
            )
        try:
            width, height, has_alpha = image_info(path)
        except (OSError, ValueError, struct.error) as error:
            validation.error("{}: {}".format(path, error))
            continue
        physical_size = tuple(sorted((width, height)))
        display_class = IPHONE_SCREENSHOT_SIZES.get(physical_size)
        if display_class is None:
            allowed = ", ".join(
                "{}x{}".format(width, height)
                for width, height in sorted(IPHONE_SCREENSHOT_SIZES)
            )
            validation.error(
                "{}: {}x{} is not an approved 6.9-inch or 6.5-inch size ({})".format(
                    path, width, height, allowed
                )
            )
        else:
            physical_sizes.add(physical_size)
            display_classes.add(display_class)
        if has_alpha:
            validation.error("{}: alpha/transparency is not allowed".format(path))

    if len(physical_sizes) > 1:
        validation.error(
            "{}: use one exact physical resolution throughout the screenshot set".format(
                SCREENSHOT_ROOT
            )
        )
    if len(display_classes) > 1:
        validation.error(
            "{}: do not mix 6.9-inch and 6.5-inch screenshot classes".format(
                SCREENSHOT_ROOT
            )
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="validate metadata while final screenshots are still pending",
    )
    arguments = parser.parse_args(argv)

    validation = Validation()
    values = validate_metadata(validation)
    if not arguments.metadata_only:
        validate_screenshots(validation)

    for warning in validation.warnings:
        print("WARNING: {}".format(warning))
    for error in validation.errors:
        print("ERROR: {}".format(error), file=sys.stderr)

    if validation.errors:
        print(
            "FAILED: {} error(s), {} warning(s)".format(
                len(validation.errors), len(validation.warnings)
            ),
            file=sys.stderr,
        )
        return 1

    checked = "metadata" if arguments.metadata_only else "metadata and screenshots"
    print(
        "PASS: {} field files validated for version {} build {}; {} checked; {} warning(s)".format(
            len(values), EXPECTED_VERSION, EXPECTED_BUILD, checked, len(validation.warnings)
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
