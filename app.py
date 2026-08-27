from flask import Flask, request, jsonify
import hashlib
import json
import math

app = Flask(__name__)

SAFE_MAX = 9007199254740991
FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def utf8_key(s):
    return s.encode("utf-8")


def sort_utf8(values):
    return sorted(values, key=utf8_key)


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def sha256_json(obj):
    return sha256_text(compact_json(obj))


def safe_int(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= SAFE_MAX
    )


def finite(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def rounded(x):
    return round(float(x), 12)


def unique_strings(x):
    return (
        isinstance(x, list)
        and all(
            isinstance(v, str) and v != ""
            for v in x
        )
        and len(x) == len(set(x))
    )


def reason_list(values):
    return sorted(
        set(values),
        key=utf8_key
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def make_inventory(files):
    if not isinstance(files, dict) or not files:
        return None

    names = list(files.keys())

    if any(
        not isinstance(n, str) or n == ""
        for n in names
    ):
        return None

    if any(
        not isinstance(files[n], str)
        for n in names
    ):
        return None

    inventory = []

    for name in sort_utf8(names):
        raw = files[name].encode("utf-8")

        inventory.append({
            "name": name,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()
        })

    total = sum(
        x["bytes"]
        for x in inventory
    )

    if total > SAFE_MAX:
        return None

    digest = sha256_json(inventory)

    return {
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": digest
    }


# ============================================================
# FREEZE INPUT
# ============================================================

def valid_freeze_input(data):

    if not isinstance(data, dict):
        return False

    if data.get("phase") != "freeze":
        return False

    freeze_id = data.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or len(freeze_id) > 128
    ):
        return False

    calibration = data.get(
        "calibrationDigest"
    )

    tokenizer = data.get(
        "tokenizerDigest"
    )

    if (
        not isinstance(calibration, str)
        or not calibration
    ):
        return False

    if (
        not isinstance(tokenizer, str)
        or not tokenizer
    ):
        return False

    allowed = data.get(
        "allowedUnsupportedReasons"
    )

    if not unique_strings(allowed):
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

    for c in candidates:

        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        names.append(name)

        if not isinstance(
            c.get("files"),
            dict
        ):
            return False

        if not isinstance(
            c.get("loadable"),
            bool
        ):
            return False

        cd = c.get(
            "calibrationDigest"
        )

        td = c.get(
            "tokenizerDigest"
        )

        if (
            not isinstance(cd, str)
            or not cd
        ):
            return False

        if (
            not isinstance(td, str)
            or not td
        ):
            return False

        # unsupportedReason may be null OR a non-empty string
        reason = c.get(
            "unsupportedReason"
        )

        if reason is not None:
            if (
                not isinstance(reason, str)
                or not reason
            ):
                return False

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_one(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons
):

    name = candidate["name"]

    manifest = make_inventory(
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
            "reasonCodes": ["INVALID_INPUT"]
        }

    reasons = []

    unsupported = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Unsupported reason
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

        reasons.append(
            "UNALLOWED_UNSUPPORTED_REASON"
        )

    # --------------------------------------------------------
    # Loadability
    # --------------------------------------------------------

    if not candidate["loadable"]:
        reasons.append(
            "NOT_LOADABLE"
        )

    # --------------------------------------------------------
    # Calibration
    # --------------------------------------------------------

    if (
        candidate["calibrationDigest"]
        != request_calibration
    ):
        reasons.append(
            "CALIBRATION_MISMATCH"
        )

    # --------------------------------------------------------
    # Tokenizer
    # --------------------------------------------------------

    if (
        candidate["tokenizerDigest"]
        != request_tokenizer
    ):
        reasons.append(
            "TOKENIZER_MISMATCH"
        )

    reasons = reason_list(reasons)

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
# FREEZE OPERATION
# ============================================================

def do_freeze(data):

    if not valid_freeze_input(data):
        return {
            "error": "INVALID_INPUT"
        }, 400

    freeze_id = data["freezeId"]

    # Fingerprint entire original request.
    fingerprint = sha256_json(data)

    if freeze_id in FREEZES:

        stored = FREEZES[freeze_id]

        if stored["fingerprint"] == fingerprint:
            return stored["response"], 200

        return {
            "error": "FREEZE_ID_CONFLICT"
        }, 409

    candidates = []

    for candidate in data["candidates"]:

        candidates.append(
            freeze_one(
                candidate,
                data["calibrationDigest"],
                data["tokenizerDigest"],
                data["allowedUnsupportedReasons"]
            )
        )

    candidates.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": candidates
    }

    FREEZES[freeze_id] = {
        "fingerprint": fingerprint,
        "response": response
    }

    return response, 200


# ============================================================
# SELECT VALIDATION
# ============================================================

def valid_select_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder"
    ]

    if any(
        k not in policy
        for k in required
    ):
        return False

    if not safe_int(
        policy["maxBytes"]
    ):
        return False

    if not finite(
        policy["aggregateFloor"]
    ):
        return False

    if not 0 <= float(
        policy["aggregateFloor"]
    ) <= 1:
        return False

    slices = policy[
        "requiredSlices"
    ]

    if not isinstance(slices, dict):
        return False

    for name, floor in slices.items():

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        if not finite(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    if not finite(
        policy["maxLatencyMs"]
    ):
        return False

    if float(
        policy["maxLatencyMs"]
    ) < 0:
        return False

    if not unique_strings(
        policy["candidateOrder"]
    ):
        return False

    return True


# ============================================================
# MANIFEST CHECK
# ============================================================

def check_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if (
        not isinstance(inventory, list)
        or len(inventory) == 0
    ):
        return False, None

    names = []

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None

        name = item["name"]

        if (
            not isinstance(name, str)
            or not name
        ):
            return False, None

        if not safe_int(
            item["bytes"]
        ):
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

    if len(names) != len(set(names)):
        return False, None

    if names != sort_utf8(names):
        return False, None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    if total > SAFE_MAX:
        return False, None

    digest = sha256_json(
        inventory
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != digest:
        return False, None

    return True, total


# ============================================================
# PREDICTIONS
# ============================================================

def predictions_for(
    rows,
    candidate_name
):

    if (
        not isinstance(rows, list)
        or len(rows) == 0
    ):
        return None, {}, False

    checked = []

    for row in rows:

        if not isinstance(row, dict):
            return None, {}, False

        if (
            "label" not in row
            or "slice" not in row
            or "predictions" not in row
        ):
            return None, {}, False

        label = row["label"]
        slice_name = row["slice"]
        predictions = row["predictions"]

        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            return None, {}, False

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            return None, {}, False

        if not isinstance(
            predictions,
            dict
        ):
            return None, {}, False

        if candidate_name not in predictions:
            return None, {}, False

        prediction = predictions[
            candidate_name
        ]

        if (
            not isinstance(prediction, int)
            or isinstance(prediction, bool)
            or prediction not in (0, 1)
        ):
            return None, {}, False

        checked.append(
            (
                label,
                prediction,
                slice_name
            )
        )

    correct = sum(
        label == prediction
        for label, prediction, _ in checked
    )

    aggregate = rounded(
        correct / len(checked)
    )

    slices = {}

    slice_names = sort_utf8(
        set(
            x[2]
            for x in checked
        )
    )

    for name in slice_names:

        subset = [
            x
            for x in checked
            if x[2] == name
        ]

        correct_slice = sum(
            x[0] == x[1]
            for x in subset
        )

        slices[name] = rounded(
            correct_slice / len(subset)
        )

    return aggregate, slices, True


# ============================================================
# SELECT
# ============================================================

def do_select(data):

    freeze_id = data.get(
        "freezeId"
    )

    if not isinstance(
        freeze_id,
        str
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

    latencies = data.get(
        "latencies"
    )

    # Contract-level invalid input.
    if (
        not isinstance(candidates, list)
        or not isinstance(rows, list)
        or not isinstance(policy, dict)
        or not isinstance(latencies, dict)
    ):
        return {
            "error": "INVALID_INPUT"
        }, 400

    stored = FREEZES.get(
        freeze_id
    )

    # --------------------------------------------------------
    # Unknown freeze.
    # --------------------------------------------------------

    if stored is None:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    frozen = stored["response"]["candidates"]

    # --------------------------------------------------------
    # Supplied frozen candidate array must exactly match.
    # --------------------------------------------------------

    if candidates != frozen:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Policy.
    # --------------------------------------------------------

    if not valid_select_policy(policy):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    frozen_names = [
        c["name"]
        for c in frozen
    ]

    order = policy[
        "candidateOrder"
    ]

    if (
        len(order) != len(frozen_names)
        or len(set(order)) != len(order)
        or set(order) != set(frozen_names)
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    results_by_name = {}

    for candidate in frozen:

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
            check_manifest(candidate)
        )

        if not manifest_ok:
            reasons.append(
                "INVALID_MANIFEST"
            )
            total_bytes = None

        # ----------------------------------------------------
        # Latency.
        # ----------------------------------------------------

        latency_raw = latencies.get(name)

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
            predictions_for(
                rows,
                name
            )
        )

        if not prediction_ok:

            reasons.append(
                "INVALID_PREDICTIONS"
            )

        else:

            if aggregate < float(
                policy["aggregateFloor"]
            ):
                reasons.append(
                    "AGGREGATE_FLOOR"
                )

            required = policy[
                "requiredSlices"
            ]

            for slice_name in sort_utf8(
                required.keys()
            ):

                if slice_name not in slices:

                    reasons.append(
                        "MISSING_SLICE:"
                        + slice_name
                    )

                elif slices[
                    slice_name
                ] < float(
                    required[slice_name]
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

        reasons = reason_list(
            reasons
        )

        results_by_name[name] = {
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
        results_by_name[name]
        for name in order
    ]

    order_index = {
        name: i
        for i, name in enumerate(order)
    }

    winners = [
        r
        for r in results
        if r["admitted"]
    ]

    winners.sort(
        key=lambda r: (
            r["totalBytes"],
            r["latencyMs"],
            order_index[r["name"]]
        )
    )

    if winners:

        winner = winners[0]

        selected = winner["name"]

        # packageManifest is exactly the recorded winner object.
        package_manifest = winner

    else:

        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }, 200


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/quantize")
def quantize():

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

    phase = data.get("phase")

    if phase == "freeze":
        result, status = do_freeze(data)
        return jsonify(result), status

    if phase == "select":
        result, status = do_select(data)
        return jsonify(result), status

    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


@app.get("/")
def index():
    return "Deterministic quantization gate is running", 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
