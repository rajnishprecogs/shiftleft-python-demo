import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    with path.open("w", encoding="utf-8") as open_file:
        # vulnerability: Directory Traversal
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
from flask import request, jsonify
import subprocess
import shlex

def grep_processes():
    name = request.args.get("name")
    if not name or not isinstance(name, str):
        return jsonify({"error": "Invalid process name"}), 400
    # FIX: Use subprocess without shell=True and pass arguments as a list to avoid shell injection
    try:
        # Use 'ps aux' and filter in Python instead of using shell pipelines
        res = subprocess.run(["ps", "aux"], capture_output=True, check=True)
        output = res.stdout.decode("utf-8")
        lines = output.splitlines()
        names = []
        for line in lines[1:]:  # skip header
            if name in line:
                parts = line.split()
                if len(parts) > 10:
                    names.append(parts[10])  # $11 in awk is index 10 in Python (0-based)
        return jsonify({"success": True, "names": names})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# This fix is secure because it:
# - Avoids shell=True and does not concatenate user input into a shell command.
# - Uses subprocess with a list of arguments, preventing shell interpretation.
# - Filters process names in Python, eliminating the risk of command injection.
# - Handles errors gracefully and validates input.


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
