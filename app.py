from flask import Flask, request, jsonify
import hashlib
import json
import math

app = Flask(__name__)

SAFE_MAX = 9007199254740991

# Persistent for the lifetime of the Render process.
# Each freezeId owns exactly one frozen response.
FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def utf8_key(value):
    return value.encode("utf-8")


def sort_utf8(values):
    return sorted(values, key=utf8_key)


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value):
    return sha256_text(compact_json(value))


def safe_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
    )


def positive_safe_int(value):
    return (
        safe_int(value)
        and value > 0
    )


def finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def rounded(value):
    return round(float(value), 12)


def nonempty_string(value):
    return (
        isinstance(value, str)
        and value != ""
    )


def unique_nonempty_strings(value):
    if not isinstance(value, list):
        return False

    if any(
        not isinstance(x, str) or x == ""
        for x in value
    ):
        return False

    return len(value) == len(set(value))


def normalize_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    """
    Returns:
        {
            inventory: [...],
            totalBytes: int,
            packageDigest: str
        }

    Returns None if files itself is invalid.
    """

    if not isinstance(files, dict):
        return None

    if len(files) == 0:
        return None

    names = list(files.keys())

    # JSON object keys must be strings.
    if any(
        not isinstance(name, str) or name == ""
        for name in names
    ):
        return None

    # File contents must be strings.
    if any(
        not isinstance(files[name], str)
        for name in names
    ):
        return None

    inventory = []

    for name in sort_utf8(names):

        raw = files[name].encode("utf-8")

        inventory.append({
            "name": name,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    total = sum(
        item["bytes"]
        for item in inventory
    )

    if total > SAFE_MAX:
        return None

    package_digest = sha256_json(
        inventory
    )

    return {
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package_digest
    }


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def validate_freeze_request(data):

    if not isinstance(data, dict):
        return False

    if data.get("phase") != "freeze":
        return False

    freeze_id = data.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or freeze_id == ""
        or len(freeze_id) > 128
    ):
        return False

    calibration = data.get(
        "calibrationDigest"
    )

    tokenizer = data.get(
        "tokenizerDigest"
    )

    if not nonempty_string(calibration):
        return False

    if not nonempty_string(tokenizer):
        return False

    allowed = data.get(
        "allowedUnsupportedReasons"
    )

    if not unique_nonempty_strings(allowed):
        return False

    candidates = data.get(
        "candidates"
    )

    if (
        not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

        files = candidate.get("files")

        if not isinstance(files, dict):
            return False

        # Empty files are a candidate-level invalid-file case,
        # not a whole-request INVALID_INPUT case.

        if not isinstance(
            candidate.get("loadable"),
            bool
        ):
            return False

        candidate_calibration = candidate.get(
            "calibrationDigest"
        )

        candidate_tokenizer = candidate.get(
            "tokenizerDigest"
        )

        if not nonempty_string(
            candidate_calibration
        ):
            return False

        if not nonempty_string(
            candidate_tokenizer
        ):
            return False

        if "unsupportedReason" in candidate:

            reason = candidate.get(
                "unsupportedReason"
            )

            if reason is not None:

                if not nonempty_string(reason):
                    return False

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FREEZE ONE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons
):

    name = candidate["name"]

    manifest = build_inventory(
        candidate["files"]
    )

    # Invalid file object.
    if manifest is None:

        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ]
        }

    unsupported = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Explicitly allowed unsupported reason.
    # --------------------------------------------------------

    if unsupported is not None:

        if unsupported in allowed_reasons:

            return {
                "name": name,
                "status": "unsupported",
                "inventory": manifest["inventory"],
                "totalBytes": manifest["totalBytes"],
                "packageDigest": manifest["packageDigest"],
                "reasonCodes": []
            }

    reasons = []

    # --------------------------------------------------------
    # Unsupported reason is present but not allowed.
    # --------------------------------------------------------

    if unsupported is not None:

        reasons.append(
            "UNALLOWED_UNSUPPORTED_REASON"
        )

    # --------------------------------------------------------
    # Loadability.
    # --------------------------------------------------------

    if candidate["loadable"] is not True:

        reasons.append(
            "NOT_LOADABLE"
        )

    # --------------------------------------------------------
    # Calibration lineage.
    # --------------------------------------------------------

    if (
        candidate["calibrationDigest"]
        != request_calibration
    ):

        reasons.append(
            "CALIBRATION_MISMATCH"
        )

    # --------------------------------------------------------
    # Tokenizer lineage.
    # --------------------------------------------------------

    if (
        candidate["tokenizerDigest"]
        != request_tokenizer
    ):

        reasons.append(
            "TOKENIZER_MISMATCH"
        )

    reasons = normalize_codes(
        reasons
    )

    if reasons:

        status = "invalid"

    else:

        status = "frozen"

    return {
        "name": name,
        "status": status,
        "inventory": manifest["inventory"],
        "totalBytes": manifest["totalBytes"],
        "packageDigest": manifest["packageDigest"],
        "reasonCodes": reasons
    }


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(data):

    if not validate_freeze_request(data):

        return {
            "error": "INVALID_INPUT"
        }, 400

    freeze_id = data["freezeId"]

    # Entire request is the identity of the freeze.
    fingerprint = sha256_json(data)

    # --------------------------------------------------------
    # Replay / conflict.
    # --------------------------------------------------------

    if freeze_id in FREEZES:

        stored = FREEZES[freeze_id]

        if stored["fingerprint"] == fingerprint:

            return stored["response"], 200

        return {
            "error": "FREEZE_ID_CONFLICT"
        }, 409

    # --------------------------------------------------------
    # Construct frozen candidates.
    # --------------------------------------------------------

    frozen_candidates = []

    for candidate in data["candidates"]:

        frozen_candidates.append(
            freeze_candidate(
                candidate,
                data["calibrationDigest"],
                data["tokenizerDigest"],
                data["allowedUnsupportedReasons"]
            )
        )

    frozen_candidates.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": frozen_candidates
    }

    # --------------------------------------------------------
    # Persist only after the complete freeze succeeds.
    # --------------------------------------------------------

    FREEZES[freeze_id] = {
        "fingerprint": fingerprint,
        "response": response
    }

    return response, 200


# ============================================================
# SELECT POLICY
# ============================================================

def validate_select_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder"
    }

    if not required.issubset(policy.keys()):
        return False

    # Size ceiling.
    if not safe_int(
        policy["maxBytes"]
    ):
        return False

    # Aggregate floor.
    if not finite(
        policy["aggregateFloor"]
    ):
        return False

    if not (
        0 <= float(
            policy["aggregateFloor"]
        ) <= 1
    ):
        return False

    # Required slices.
    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict
    ):
        return False

    for name, floor in required_slices.items():

        if not nonempty_string(name):
            return False

        if not finite(floor):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    # Latency ceiling.
    if not finite(
        policy["maxLatencyMs"]
    ):
        return False

    if float(
        policy["maxLatencyMs"]
    ) < 0:
        return False

    # Candidate order.
    if not unique_nonempty_strings(
        policy["candidateOrder"]
    ):
        return False

    return True


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(
        inventory,
        list
    ):
        return False, None

    if len(inventory) == 0:
        return False, None

    names = []

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        # Exact inventory keys.
        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256"
        ]:
            return False, None

        name = item["name"]

        if not nonempty_string(name):
            return False, None

        byte_count = item["bytes"]

        if not safe_int(byte_count):
            return False, None

        digest = item["sha256"]

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(
                c not in "0123456789abcdef"
                for c in digest
            )
        ):
            return False, None

        names.append(name)

    # Unique filenames.
    if len(names) != len(set(names)):
        return False, None

    # UTF-8 filename order.
    if names != sort_utf8(names):
        return False, None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    if total > SAFE_MAX:
        return False, None

    # Recompute digest from inventory.
    digest = sha256_json(
        inventory
    )

    submitted_total = candidate.get(
        "totalBytes"
    )

    if (
        not safe_int(submitted_total)
        or submitted_total != total
    ):
        return False, None

    if candidate.get(
        "packageDigest"
    ) != digest:
        return False, None

    return True, total


# ============================================================
# PREDICTIONS
# ============================================================

def calculate_predictions(
    rows,
    candidate_name
):
    """
    Returns:
      aggregate,
      slices,
      valid

    Invalid predictions:
      None, None, False
    """

    if not isinstance(rows, list):
        return None, None, False

    if len(rows) == 0:
        return None, None, False

    checked = []

    for row in rows:

        if not isinstance(row, dict):
            return None, None, False

        if (
            "label" not in row
            or "slice" not in row
            or "predictions" not in row
        ):
            return None, None, False

        label = row["label"]

        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            return None, None, False

        slice_name = row["slice"]

        if not nonempty_string(
            slice_name
        ):
            return None, None, False

        predictions = row["predictions"]

        if not isinstance(
            predictions,
            dict
        ):
            return None, None, False

        if candidate_name not in predictions:
            return None, None, False

        prediction = predictions[
            candidate_name
        ]

        if (
            not isinstance(prediction, int)
            or isinstance(prediction, bool)
            or prediction not in (0, 1)
        ):
            return None, None, False

        checked.append(
            (
                label,
                prediction,
                slice_name
            )
        )

    # Aggregate.
    correct = sum(
        1
        for label, prediction, _ in checked
        if label == prediction
    )

    aggregate = rounded(
        correct / len(checked)
    )

    # Slice accuracies.
    slice_names = sort_utf8(
        set(
            item[2]
            for item in checked
        )
    )

    slices = {}

    for slice_name in slice_names:

        subset = [
            item
            for item in checked
            if item[2] == slice_name
        ]

        slice_correct = sum(
            1
            for label, prediction, _ in subset
            if label == prediction
        )

        slices[slice_name] = rounded(
            slice_correct / len(subset)
        )

    return aggregate, slices, True


# ============================================================
# EMPTY SELECT RESULT
# ============================================================

def empty_select_response(freeze_id):
    return {
        "freezeId": freeze_id,
        "selected": None,
        "results": [],
        "packageManifest": None
    }


# ============================================================
# SELECT
# ============================================================

def perform_select(data):

    # --------------------------------------------------------
    # Basic shape.
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return {
            "error": "INVALID_INPUT"
        }, 400

    if data.get("phase") != "select":
        return {
            "error": "INVALID_INPUT"
        }, 400

    freeze_id = data.get(
        "freezeId"
    )

    if not nonempty_string(
        freeze_id
    ):
        return {
            "error": "INVALID_INPUT"
        }, 400

    candidates = data.get(
        "candidates"
    )

    rows = data.get(
        "rows"
    )

    policy = data.get(
        "policy"
    )

    # Latencies are optional at request-shape level.
    # Missing/invalid values become INVALID_LINEAGE.
    latencies = data.get(
        "latencies",
        {}
    )

    # The contract specifically requires arrays + policy object.
    if not isinstance(
        candidates,
        list
    ):
        return {
            "error": "INVALID_INPUT"
        }, 400

    if not isinstance(
        rows,
        list
    ):
        return {
            "error": "INVALID_INPUT"
        }, 400

    if not isinstance(
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
        # Treat malformed latency container as lineage failure,
        # not request-shape failure.
        latencies = {}

    # --------------------------------------------------------
    # Empty candidate array is invalid.
    # --------------------------------------------------------

    if len(candidates) == 0:
        return {
            "error": "INVALID_INPUT"
        }, 400

    # --------------------------------------------------------
    # Find freeze.
    # --------------------------------------------------------

    stored = FREEZES.get(
        freeze_id
    )

    if stored is None:

        # We can still produce deterministic NOT_FROZEN
        # results from the supplied candidate array.
        results = []

        for supplied in candidates:

            if isinstance(supplied, dict):
                name = supplied.get(
                    "name"
                )
            else:
                name = None

            if not nonempty_string(name):
                # Bad supplied candidate shape is request-invalid.
                return {
                    "error": "INVALID_INPUT"
                }, 400

            results.append({
                "name": name,
                "aggregate": None,
                "slices": None,
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "NOT_FROZEN"
                ]
            })

        results.sort(
            key=lambda x: utf8_key(
                x["name"]
            )
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    frozen_candidates = stored[
        "response"
    ]["candidates"]

    # --------------------------------------------------------
    # Candidate array must exactly equal frozen response.
    # --------------------------------------------------------

    if candidates != frozen_candidates:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Validate policy.
    # --------------------------------------------------------

    policy_valid = validate_select_policy(
        policy
    )

    if not policy_valid:

        # Candidate results can still be deterministic.
        results = []

        for candidate in frozen_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": None,
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ]
            })

        order = [
            c["name"]
            for c in frozen_candidates
        ]

        results.sort(
            key=lambda x: (
                order.index(x["name"])
                if x["name"] in order
                else len(order),
                utf8_key(x["name"])
            )
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    frozen_names = [
        candidate["name"]
        for candidate in frozen_candidates
    ]

    candidate_order = policy[
        "candidateOrder"
    ]

    # --------------------------------------------------------
    # Same unique candidate set.
    # --------------------------------------------------------

    if (
        len(candidate_order)
        != len(frozen_names)
        or len(set(candidate_order))
        != len(candidate_order)
        or set(candidate_order)
        != set(frozen_names)
    ):

        results = []

        for candidate in frozen_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": None,
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ]
            })

        results.sort(
            key=lambda x: (
                candidate_order.index(
                    x["name"]
                )
                if x["name"]
                in candidate_order
                else len(candidate_order),
                utf8_key(x["name"])
            )
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Evaluate every frozen candidate.
    # --------------------------------------------------------

    result_by_name = {}

    for candidate in frozen_candidates:

        name = candidate["name"]

        reasons = []

        # ----------------------------------------------------
        # Frozen status.
        # ----------------------------------------------------

        if candidate["status"] != "frozen":
            reasons.append(
                "NOT_FROZEN"
            )

        # ----------------------------------------------------
        # Manifest.
        # ----------------------------------------------------

        manifest_ok, total_bytes = (
            validate_manifest(candidate)
        )

        if not manifest_ok:

            reasons.append(
                "INVALID_MANIFEST"
            )

            total_bytes = None

        # ----------------------------------------------------
        # Latency.
        # ----------------------------------------------------

        latency_raw = latencies.get(
            name
        )

        if not finite(latency_raw):

            latency = None

            reasons.append(
                "INVALID_LINEAGE"
            )

        elif float(latency_raw) < 0:

            latency = None

            reasons.append(
                "INVALID_LINEAGE"
            )

        else:

            latency = rounded(
                latency_raw
            )

            if latency > float(
                policy["maxLatencyMs"]
            ):

                reasons.append(
                    "LATENCY_LIMIT"
                )

        # ----------------------------------------------------
        # Predictions.
        # ----------------------------------------------------

        aggregate, slices, prediction_ok = (
            calculate_predictions(
                rows,
                name
            )
        )

        if not prediction_ok:

            reasons.append(
                "INVALID_PREDICTIONS"
            )

            aggregate = None
            slices = None

        else:

            # Aggregate floor.
            if aggregate < float(
                policy["aggregateFloor"]
            ):

                reasons.append(
                    "AGGREGATE_FLOOR"
                )

            # Required slices.
            required_slices = policy[
                "requiredSlices"
            ]

            for slice_name in sort_utf8(
                required_slices.keys()
            ):

                if slice_name not in slices:

                    reasons.append(
                        "MISSING_SLICE:"
                        + slice_name
                    )

                elif slices[
                    slice_name
                ] < float(
                    required_slices[
                        slice_name
                    ]
                ):

                    reasons.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

        # ----------------------------------------------------
        # Size.
        # ----------------------------------------------------

        if total_bytes is not None:

            if total_bytes > policy[
                "maxBytes"
            ]:

                reasons.append(
                    "SIZE_LIMIT"
                )

        reasons = normalize_codes(
            reasons
        )

        result_by_name[name] = {
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": len(reasons) == 0,
            "reasonCodes": reasons
        }

    # --------------------------------------------------------
    # Results in candidateOrder.
    # --------------------------------------------------------

    results = [
        result_by_name[name]
        for name in candidate_order
    ]

    order_index = {
        name: index
        for index, name in enumerate(
            candidate_order
        )
    }

    # --------------------------------------------------------
    # Winner:
    # smaller bytes
    # lower latency
    # candidate order
    # --------------------------------------------------------

    winners = [
        result
        for result in results
        if result["admitted"]
    ]

    winners.sort(
        key=lambda result: (
            result["totalBytes"],
            result["latencyMs"],
            order_index[result["name"]]
        )
    )

    if not winners:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    winner = winners[0]

    selected = winner["name"]

    # IMPORTANT:
    # packageManifest is the recorded frozen candidate object,
    # NOT the evaluation result.
    winner_manifest = None

    for candidate in frozen_candidates:

        if candidate["name"] == selected:

            winner_manifest = candidate
            break

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": winner_manifest
    }, 200


# ============================================================
# /quantize
# ============================================================

@app.post("/quantize")
def quantize():

    # --------------------------------------------------------
    # Must be JSON.
    # --------------------------------------------------------

    if not request.is_json:

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    try:
        data = request.get_json(
            silent=False
        )
    except Exception:

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    if not isinstance(data, dict):

        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    phase = data.get(
        "phase"
    )

    # --------------------------------------------------------
    # Freeze.
    # --------------------------------------------------------

    if phase == "freeze":

        response, status = perform_freeze(
            data
        )

        return jsonify(
            response
        ), status

    # --------------------------------------------------------
    # Select.
    # --------------------------------------------------------

    if phase == "select":

        response, status = perform_select(
            data
        )

        return jsonify(
            response
        ), status

    # --------------------------------------------------------
    # Unknown / missing phase.
    # --------------------------------------------------------

    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def health():

    return (
        "Deterministic quantization gate is running",
        200
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
