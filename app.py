from flask import Flask, request, jsonify
import hashlib
import json
import math

app = Flask(__name__)

SAFE_MAX = 9007199254740991

# Stateful freeze storage.
# freezeId -> {
#     "fingerprint": ...,
#     "response": ...
# }
FREEZES = {}


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8_key(value):
    return value.encode("utf-8")


def sorted_utf8(values):
    return sorted(values, key=utf8_key)


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sha256_utf8(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def sha256_json(value):
    return hashlib.sha256(
        compact_json(value).encode("utf-8")
    ).hexdigest()


def is_safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
    )


def is_finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def round12(value):
    return round(float(value), 12)


def unique_nonempty_strings(value):
    return (
        isinstance(value, list)
        and all(
            isinstance(x, str) and x != ""
            for x in value
        )
        and len(value) == len(set(value))
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(name, files):
    """
    Returns:
      inventory,
      totalBytes,
      packageDigest

    or:
      [], None, None
    """

    if not isinstance(files, dict):
        return [], None, None

    if len(files) == 0:
        return [], None, None

    filenames = list(files.keys())

    # Every filename must be a non-empty string.
    if any(
        not isinstance(filename, str)
        or filename == ""
        for filename in filenames
    ):
        return [], None, None

    # Dictionary keys are already unique by JSON semantics,
    # but explicitly verify the condition.
    if len(filenames) != len(set(filenames)):
        return [], None, None

    # Every file value must be a string.
    if any(
        not isinstance(files[filename], str)
        for filename in filenames
    ):
        return [], None, None

    inventory = []

    for filename in sorted_utf8(filenames):

        content = files[filename]

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": hashlib.sha256(
                raw
            ).hexdigest()
        })

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_json(
        inventory
    )

    return (
        inventory,
        total_bytes,
        package_digest
    )


# ============================================================
# FREEZE VALIDATION
# ============================================================

def validate_freeze_request(data):
    required = {
        "phase",
        "freezeId",
        "calibrationDigest",
        "tokenizerDigest",
        "allowedUnsupportedReasons",
        "candidates",
    }

    if not required.issubset(data.keys()):
        return False

    freeze_id = data["freezeId"]

    if (
        not isinstance(freeze_id, str)
        or freeze_id == ""
        or len(freeze_id) > 128
    ):
        return False

    if (
        not isinstance(
            data["calibrationDigest"],
            str
        )
        or data["calibrationDigest"] == ""
    ):
        return False

    if (
        not isinstance(
            data["tokenizerDigest"],
            str
        )
        or data["tokenizerDigest"] == ""
    ):
        return False

    allowed = data[
        "allowedUnsupportedReasons"
    ]

    if not unique_nonempty_strings(
        allowed
    ):
        return False

    candidates = data["candidates"]

    if (
        not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return False

    names = []

    for candidate in candidates:

        if not isinstance(
            candidate,
            dict
        ):
            return False

        required_candidate = {
            "name",
            "files",
            "loadable",
            "calibrationDigest",
            "tokenizerDigest",
            "unsupportedReason",
        }

        if not required_candidate.issubset(
            candidate.keys()
        ):
            return False

        name = candidate["name"]

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        names.append(name)

        if not isinstance(
            candidate["loadable"],
            bool
        ):
            return False

        if not isinstance(
            candidate["calibrationDigest"],
            str
        ) or candidate[
            "calibrationDigest"
        ] == "":
            return False

        if not isinstance(
            candidate["tokenizerDigest"],
            str
        ) or candidate[
            "tokenizerDigest"
        ] == "":
            return False

        unsupported = candidate[
            "unsupportedReason"
        ]

        if unsupported is not None:
            if (
                not isinstance(
                    unsupported,
                    str
                )
                or unsupported == ""
            ):
                return False

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons
):

    name = candidate["name"]

    inventory, total_bytes, package_digest = (
        build_inventory(
            name,
            candidate["files"]
        )
    )

    # Invalid files.
    if total_bytes is None:

        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    reasons = []

    unsupported_reason = candidate[
        "unsupportedReason"
    ]

    # --------------------------------------------------------
    # Unsupported reason
    # --------------------------------------------------------

    if unsupported_reason is not None:

        if unsupported_reason not in allowed_reasons:

            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        else:
            # Allowed unsupported reason means candidate
            # is explicitly unsupported.
            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": [],
            }

    # --------------------------------------------------------
    # Loadability
    # --------------------------------------------------------

    if not candidate["loadable"]:

        reasons.append(
            "NOT_LOADABLE"
        )

    # --------------------------------------------------------
    # Calibration lineage
    # --------------------------------------------------------

    if (
        candidate["calibrationDigest"]
        != request_calibration
    ):

        reasons.append(
            "CALIBRATION_MISMATCH"
        )

    # --------------------------------------------------------
    # Tokenizer lineage
    # --------------------------------------------------------

    if (
        candidate["tokenizerDigest"]
        != request_tokenizer
    ):

        reasons.append(
            "TOKENIZER_MISMATCH"
        )

    reasons = sorted(
        set(reasons),
        key=utf8_key
    )

    if reasons:

        status = "invalid"

    else:

        status = "frozen"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": reasons,
    }


# ============================================================
# FREEZE
# ============================================================

def freeze(data):

    if not validate_freeze_request(
        data
    ):
        return (
            {
                "error": "INVALID_INPUT"
            },
            400
        )

    freeze_id = data[
        "freezeId"
    ]

    # --------------------------------------------------------
    # Fingerprint the complete request.
    # --------------------------------------------------------

    fingerprint = sha256_json(
        data
    )

    existing = FREEZES.get(
        freeze_id
    )

    if existing is not None:

        if existing[
            "fingerprint"
        ] == fingerprint:

            return (
                existing["response"],
                200
            )

        return (
            {
                "error": "FREEZE_ID_CONFLICT"
            },
            409
        )

    # --------------------------------------------------------
    # Build frozen candidates.
    # --------------------------------------------------------

    result_candidates = []

    for candidate in data[
        "candidates"
    ]:

        result_candidates.append(
            freeze_candidate(
                candidate,
                data[
                    "calibrationDigest"
                ],
                data[
                    "tokenizerDigest"
                ],
                data[
                    "allowedUnsupportedReasons"
                ]
            )
        )

    # Sort candidate response by UTF-8 name.
    result_candidates.sort(
        key=lambda x: utf8_key(
            x["name"]
        )
    )

    response = {
        "freezeId": freeze_id,
        "candidates": result_candidates,
    }

    # Persist ONLY successful validation.
    FREEZES[freeze_id] = {
        "fingerprint": fingerprint,
        "response": response,
    }

    return response, 200


# ============================================================
# SELECT POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if not required.issubset(
        policy.keys()
    ):
        return False

    if not is_safe_integer(
        policy["maxBytes"]
    ):
        return False

    if not is_finite_number(
        policy["aggregateFloor"]
    ):
        return False

    if not 0 <= float(
        policy["aggregateFloor"]
    ) <= 1:
        return False

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict
    ):
        return False

    for name, floor in required_slices.items():

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        if not is_finite_number(
            floor
        ):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    if not is_finite_number(
        policy["maxLatencyMs"]
    ):
        return False

    if float(
        policy["maxLatencyMs"]
    ) < 0:
        return False

    if not unique_nonempty_strings(
        policy["candidateOrder"]
    ):
        return False

    return True


# ============================================================
# FROZEN CANDIDATE COMPARISON
# ============================================================

def candidates_exactly_equal(
    supplied,
    frozen
):
    """
    Exact JSON structural equality after comparing
    the recorded response candidate objects.
    """

    if not isinstance(
        supplied,
        list
    ):
        return False

    if not isinstance(
        frozen,
        list
    ):
        return False

    if len(supplied) != len(frozen):
        return False

    # Candidate order supplied by the grader must exactly
    # equal the frozen response.
    for a, b in zip(
        supplied,
        frozen
    ):
        if a != b:
            return False

    return True


# ============================================================
# MANIFEST RECOMPUTATION
# ============================================================

def recompute_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(
        inventory,
        list
    ):
        return False, None, None

    # Inventory must be non-empty.
    if len(inventory) == 0:
        return False, None, None

    names = []

    for item in inventory:

        if not isinstance(
            item,
            dict
        ):
            return False, None, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None, None

        name = item["name"]
        bytes_value = item["bytes"]
        digest = item["sha256"]

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False, None, None

        if not is_safe_integer(
            bytes_value
        ):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(
                c not in "0123456789abcdef"
                for c in digest
            )
        ):
            return False, None, None

        names.append(name)

    if len(names) != len(set(names)):
        return False, None, None

    if names != sorted_utf8(names):
        return False, None, None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    if total > SAFE_MAX:
        return False, None, None

    package_digest = sha256_json(
        inventory
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None, None

    if candidate.get(
        "packageDigest"
    ) != package_digest:
        return False, None, None

    return (
        True,
        total,
        package_digest
    )


# ============================================================
# PREDICTION ACCURACY
# ============================================================

def compute_accuracy(
    rows,
    candidate_name,
    required_slices
):

    if not isinstance(rows, list):
        return (
            None,
            {},
            ["INVALID_PREDICTIONS"]
        )

    if len(rows) == 0:
        return (
            None,
            {},
            ["INVALID_PREDICTIONS"]
        )

    valid_rows = []

    for row in rows:

        if not isinstance(
            row,
            dict
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        if (
            "label" not in row
            or "slice" not in row
            or "predictions" not in row
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        label = row["label"]
        slice_name = row["slice"]
        predictions = row[
            "predictions"
        ]

        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        if (
            not isinstance(slice_name, str)
            or slice_name == ""
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        if not isinstance(
            predictions,
            dict
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        if candidate_name not in predictions:
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        prediction = predictions[
            candidate_name
        ]

        if (
            not isinstance(prediction, int)
            or isinstance(prediction, bool)
            or prediction not in (0, 1)
        ):
            return (
                None,
                {},
                ["INVALID_PREDICTIONS"]
            )

        valid_rows.append(
            (
                label,
                prediction,
                slice_name
            )
        )

    # Aggregate.
    correct = sum(
        1
        for label, prediction, _
        in valid_rows
        if label == prediction
    )

    aggregate = round12(
        correct / len(valid_rows)
    )

    # Slice values.
    slices = {}

    for slice_name in sorted_utf8(
        set(
            row[2]
            for row in valid_rows
        )
    ):

        slice_rows = [
            row
            for row in valid_rows
            if row[2] == slice_name
        ]

        slice_correct = sum(
            1
            for label, prediction, _
            in slice_rows
            if label == prediction
        )

        slices[slice_name] = round12(
            slice_correct
            / len(slice_rows)
        )

    return aggregate, slices, []


# ============================================================
# SELECT ONE CANDIDATE
# ============================================================

def select_candidate(data):

    freeze_id = data.get(
        "freezeId"
    )

    # --------------------------------------------------------
    # Frozen ID must exist.
    # --------------------------------------------------------

    frozen = FREEZES.get(
        freeze_id
    )

    if frozen is None:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    supplied_candidates = data.get(
        "candidates"
    )

    rows = data.get(
        "rows"
    )

    policy = data.get(
        "policy"
    )

    latencies = data.get(
        "latencies"
    )

    # --------------------------------------------------------
    # Basic select input.
    # --------------------------------------------------------

    if not isinstance(
        supplied_candidates,
        list
    ) or not isinstance(
        rows,
        list
    ) or not isinstance(
        policy,
        dict
    ):

        return {
            "error": "INVALID_INPUT"
        }, 400

    if not isinstance(
        latencies,
        dict
    ):

        return {
            "error": "INVALID_INPUT"
        }, 400

    # --------------------------------------------------------
    # Exact frozen candidate response.
    # --------------------------------------------------------

    frozen_candidates = frozen[
        "response"
    ]["candidates"]

    if not candidates_exactly_equal(
        supplied_candidates,
        frozen_candidates
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    if not validate_policy(
        policy
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    # --------------------------------------------------------
    # Candidate names.
    # --------------------------------------------------------

    frozen_names = [
        candidate["name"]
        for candidate in frozen_candidates
    ]

    order = policy[
        "candidateOrder"
    ]

    if (
        len(order) != len(frozen_names)
        or set(order) != set(frozen_names)
        or len(set(order)) != len(order)
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    # --------------------------------------------------------
    # Evaluate every candidate.
    # --------------------------------------------------------

    result_map = {}

    for candidate in frozen_candidates:

        name = candidate[
            "name"
        ]

        reasons = []

        # ----------------------------------------------------
        # Frozen status / lineage.
        # ----------------------------------------------------

        if candidate[
            "status"
        ] != "frozen":

            reasons.append(
                "NOT_FROZEN"
            )

        # ----------------------------------------------------
        # Manifest integrity.
        # ----------------------------------------------------

        manifest_ok, total_bytes, _ = (
            recompute_manifest(
                candidate
            )
        )

        if not manifest_ok:

            reasons.append(
                "INVALID_MANIFEST"
            )

            total_bytes = None

        # ----------------------------------------------------
        # Frozen package digest / candidate inventory
        # is already bound to freeze response.
        # ----------------------------------------------------

        if candidate[
            "status"
        ] == "invalid":

            reasons.append(
                "INVALID_LINEAGE"
            )

        # ----------------------------------------------------
        # Latency.
        # ----------------------------------------------------

        latency = latencies.get(
            name
        )

        if not is_finite_number(
            latency
        ):

            reasons.append(
                "INVALID_LINEAGE"
            )

            latency_value = None

        elif float(latency) < 0:

            reasons.append(
                "INVALID_LINEAGE"
            )

            latency_value = None

        else:

            latency_value = float(
                latency
            )

            if latency_value > float(
                policy["maxLatencyMs"]
            ):

                reasons.append(
                    "LATENCY_LIMIT"
                )

        # ----------------------------------------------------
        # Predictions.
        # ----------------------------------------------------

        aggregate, slices, prediction_errors = (
            compute_accuracy(
                rows,
                name,
                policy[
                    "requiredSlices"
                ]
            )
        )

        reasons.extend(
            prediction_errors
        )

        # ----------------------------------------------------
        # Accuracy gates only if predictions valid.
        # ----------------------------------------------------

        if aggregate is not None:

            if aggregate < float(
                policy["aggregateFloor"]
            ):

                reasons.append(
                    "AGGREGATE_FLOOR"
                )

            for slice_name in sorted_utf8(
                policy[
                    "requiredSlices"
                ].keys()
            ):

                if slice_name not in slices:

                    reasons.append(
                        f"MISSING_SLICE:{slice_name}"
                    )

                elif slices[
                    slice_name
                ] < float(
                    policy[
                        "requiredSlices"
                    ][slice_name]
                ):

                    reasons.append(
                        f"SLICE_FLOOR:{slice_name}"
                    )

        # ----------------------------------------------------
        # Size gate.
        # ----------------------------------------------------

        if total_bytes is not None:

            if total_bytes > policy[
                "maxBytes"
            ]:

                reasons.append(
                    "SIZE_LIMIT"
                )

        # ----------------------------------------------------
        # Deduplicate/sort reason codes.
        # ----------------------------------------------------

        reasons = sorted(
            set(reasons),
            key=utf8_key
        )

        admitted = len(reasons) == 0

        result_map[name] = {
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": (
                round12(latency_value)
                if latency_value is not None
                else None
            ),
            "admitted": admitted,
            "reasonCodes": reasons,
        }

    # --------------------------------------------------------
    # Published result order = candidateOrder.
    # --------------------------------------------------------

    results = [
        result_map[name]
        for name in order
    ]

    # --------------------------------------------------------
    # Select admitted candidate.
    #
    # bytes ASC
    # latency ASC
    # candidateOrder ASC
    # --------------------------------------------------------

    order_index = {
        name: index
        for index, name
        in enumerate(order)
    }

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    admitted.sort(
        key=lambda result: (
            result["totalBytes"],
            result["latencyMs"],
            order_index[
                result["name"]
            ],
        )
    )

    if admitted:

        winner = admitted[0]

        selected = winner[
            "name"
        ]

        package_manifest = winner.copy()

    else:

        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, 200


# ============================================================
# POST /quantize
# ============================================================

@app.post("/quantize")
def quantize():

    # Must be JSON.
    if not request.is_json:

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    try:
        data = request.get_json()

    except Exception:

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    if not isinstance(
        data,
        dict
    ):

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    phase = data.get(
        "phase"
    )

    # Unknown/missing phase.
    if phase not in {
        "freeze",
        "select"
    }:

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        result, status = freeze(
            data
        )

        return jsonify(
            result
        ), status

    # --------------------------------------------------------
    # SELECT
    # --------------------------------------------------------

    result, status = select_candidate(
        data
    )

    return jsonify(
        result
    ), status


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health():

    return (
        "Deterministic quantization gate is running",
        200
    )


# ============================================================
# LOCAL SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
