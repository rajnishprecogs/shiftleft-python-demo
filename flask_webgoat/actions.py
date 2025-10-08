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
    if not name:
        return jsonify({"error": "name parameter is required"})

    # Sanitize the input to prevent command injection
    sanitized_name = shlex.quote(name)

    try:
        # Use a safer approach to execute the command
        res = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=True
        )

        # Filter the output in Python instead of using shell commands
        output_lines = res.stdout.splitlines()
        filtered_lines = [line.split()[10] for line in output_lines if sanitized_name in line]

        return jsonify({"success": True, "names": filtered_lines})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Failed to execute command", "details": str(e)})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
