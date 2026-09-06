import subprocess
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[2]
PYTHON_BIN = PROJECT_DIR / ".venv" / "bin" / "python"
APPLY_SCRIPT = PROJECT_DIR / "scripts" / "apply_rules.py"


class SystemActions:

    @staticmethod
    def apply_configuration():
        if not PYTHON_BIN.exists():
            return {
                "success": False,
                "message": "Python virtual environment not found."
            }

        if not APPLY_SCRIPT.exists():
            return {
                "success": False,
                "message": "Firewall deployment script not found."
            }

        try:
            result = subprocess.run(
                [
                    "sudo",
                    str(PYTHON_BIN),
                    str(APPLY_SCRIPT),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "message": "Firewall configuration failed.",
                    "output": result.stderr.strip(),
                }

            return {
                "success": True,
                "message": "Firewall configuration applied successfully.",
                "output": result.stdout.strip(),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Firewall configuration timed out."
            }

        except Exception as error:
            return {
                "success": False,
                "message": f"Failed to apply configuration: {error}"
            }