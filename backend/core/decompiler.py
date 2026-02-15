"""
APK Decompiler — wraps apktool and jadx to decompile APK files.
"""
import subprocess
import os
import shutil
import logging

logger = logging.getLogger(__name__)


TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tools")


class Decompiler:
    """Handles APK decompilation using apktool and jadx."""

    def __init__(self, work_dir: str = "/tmp/droidsec"):
        self.work_dir = work_dir
        self.apktool_path = os.path.join(TOOLS_DIR, "apktool")
        self.jadx_path = os.path.join(TOOLS_DIR, "jadx", "bin", "jadx")

    def decompile(self, apk_path: str, scan_id: str) -> dict:
        """
        Decompile an APK file using apktool and jadx.
        Returns paths to decompiled resources and source code.
        """
        output_dir = os.path.join(self.work_dir, scan_id)
        apktool_dir = os.path.join(output_dir, "apktool_out")
        jadx_dir = os.path.join(output_dir, "jadx_out")

        # Clean previous output
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        result = {
            "scan_id": scan_id,
            "apktool_dir": apktool_dir,
            "jadx_dir": jadx_dir,
            "manifest_path": None,
            "source_dirs": [],
            "smali_dirs": [],
            "java_dirs": [],
            "resource_dirs": [],
            "success": False,
            "errors": [],
        }

        # --- Step 1: apktool (decode resources + manifest) ---
        try:
            logger.info(f"[{scan_id}] Running apktool on {apk_path}...")
            proc = subprocess.run(
                [self.apktool_path, "d", "-f", "-o", apktool_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=300,  # 5 min for large APKs
            )
            if proc.returncode == 0:
                manifest = os.path.join(apktool_dir, "AndroidManifest.xml")
                if os.path.exists(manifest):
                    result["manifest_path"] = manifest
                res_dir = os.path.join(apktool_dir, "res")
                if os.path.exists(res_dir):
                    result["resource_dirs"].append(res_dir)
                # Collect ALL smali directories (smali, smali_classes2, etc.)
                for entry in os.listdir(apktool_dir):
                    if entry.startswith("smali"):
                        smali_dir = os.path.join(apktool_dir, entry)
                        if os.path.isdir(smali_dir):
                            result["source_dirs"].append(smali_dir)
                            result["smali_dirs"].append(smali_dir)
                logger.info(f"[{scan_id}] apktool completed. "
                           f"Smali dirs: {len([d for d in result['source_dirs'] if 'smali' in d])}")
            else:
                result["errors"].append(f"apktool error: {proc.stderr[:500]}")
                logger.warning(f"[{scan_id}] apktool failed: {proc.stderr[:200]}")
        except FileNotFoundError:
            result["errors"].append("apktool not found. Install with: sudo apt install apktool")
            logger.error("apktool not installed")
        except subprocess.TimeoutExpired:
            result["errors"].append("apktool timed out after 300 seconds")
            logger.error(f"[{scan_id}] apktool timeout")

        # --- Step 2: jadx (decompile to Java source) ---
        try:
            logger.info(f"[{scan_id}] Running jadx on {apk_path}...")
            # jadx 1.5.x: NO --decompile-all. Use --show-bad-code to get partial decompilation.
            proc = subprocess.run(
                [self.jadx_path, "--show-bad-code", "--no-res", "-d", jadx_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=600,
            )
            sources_dir = os.path.join(jadx_dir, "sources")
            if proc.returncode == 0 or os.path.exists(sources_dir):
                if os.path.exists(sources_dir):
                    result["source_dirs"].append(sources_dir)
                    result["java_dirs"].append(sources_dir)
                    # Count java files for logging
                    java_count = sum(
                        1 for _, _, files in os.walk(sources_dir)
                        for f in files if f.endswith('.java')
                    )
                    logger.info(f"[{scan_id}] jadx completed. {java_count} Java files decompiled.")
                elif os.path.exists(jadx_dir):
                    result["source_dirs"].append(jadx_dir)
                    result["java_dirs"].append(jadx_dir)
                    logger.info(f"[{scan_id}] jadx completed (output in jadx_dir root).")
            else:
                error_msg = (proc.stderr or proc.stdout or "No output").strip()
                result["errors"].append(f"jadx error: {error_msg[:500]}")
                logger.warning(f"[{scan_id}] jadx failed: {error_msg[:300]}")
        except FileNotFoundError:
            result["errors"].append("jadx not found. Install from: https://github.com/skylot/jadx/releases")
            logger.error("jadx not installed")
        except subprocess.TimeoutExpired:
            result["errors"].append("jadx timed out after 600 seconds")
            logger.error(f"[{scan_id}] jadx timeout")

        # --- Step 3: Fallback — plain zip extraction ---
        if not result["manifest_path"] and not result["source_dirs"]:
            try:
                import zipfile
                fallback_dir = os.path.join(output_dir, "zip_out")
                os.makedirs(fallback_dir, exist_ok=True)
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    zf.extractall(fallback_dir)
                manifest = os.path.join(fallback_dir, "AndroidManifest.xml")
                if os.path.exists(manifest):
                    result["manifest_path"] = manifest
                for root, dirs, files in os.walk(fallback_dir):
                    for f in files:
                        if f.endswith(('.java', '.kt', '.xml', '.smali')):
                            result["source_dirs"].append(fallback_dir)
                            break
                    if result["source_dirs"]:
                        break
                logger.info(f"[{scan_id}] Zip fallback extraction completed.")
            except Exception as e:
                result["errors"].append(f"Zip fallback failed: {e}")
                logger.error(f"[{scan_id}] Zip fallback failed: {e}")

        result["success"] = bool(result["manifest_path"] or result["source_dirs"])
        logger.info(f"[{scan_id}] Decompilation result: success={result['success']}, "
                    f"source_dirs={len(result['source_dirs'])}, "
                    f"errors={len(result['errors'])}")
        return result

    def cleanup(self, scan_id: str):
        """Remove decompiled files for a scan."""
        output_dir = os.path.join(self.work_dir, scan_id)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
