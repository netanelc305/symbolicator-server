"""
Scanning: run the same scanner ipswd uses and feed its output into a store.

Taking an IPSW apart (decrypting the AEA cryptexes, mounting the APFS volumes,
parsing the dyld_shared_cache and kernelcache, finding every function) is done
by `ipsw symbols --json`, the scan code inside ipswd, exposed as a command.
It streams one JSON record per line, grouped per Mach-O:

    {"type":"ipsw",   "id":<sha1>, "name", "version", "build", "platform", "devices":[...]}
    {"type":"dsc",    "uuid", "shared_region_start"}                   once per shared cache
    {"type":"image",  "uuid", "kind", "path", "text_start", "text_end", "dsc_uuid"?}
    {"type":"symbol", "image_uuid", "name", "start", "end"}            ...that image's symbols

Each image is handed to the store as soon as its symbols have arrived (memory
stays bounded), and the whole scan is one transaction, like ipswd's.
"""

import json
import logging
import subprocess
import tempfile
import time

log = logging.getLogger("scanner")


class AlreadyScanned(Exception):
    pass


class ScanFailed(Exception):
    pass


def scan(store, ipsw_path, *, ipsw_bin="ipsw", sigs_dir=None, pem_db=None, rescan=False):
    cmd = [ipsw_bin, "symbols", "--json", ipsw_path]
    if sigs_dir:
        cmd += ["--signatures", sigs_dir]
    if pem_db:
        cmd += ["--pem-db", pem_db]
    log.info("running %s", " ".join(cmd))

    started = time.time()
    counts = {"images": 0, "symbols": 0, "skipped": 0}
    conn = store.connect()
    with tempfile.TemporaryFile("w+") as stderr:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1 << 20)
        try:
            ipsw_id = None
            image, symbols = None, []

            def flush():
                # Hand the finished image and its symbols to the store.
                if image is None:
                    return
                note = store.save_image(conn, ipsw_id, image, symbols)
                counts["images"] += 1
                counts["symbols"] += len(symbols)
                counts["skipped"] += note.startswith("already stored")
                log.debug("%s %s: %s", image["kind"], image["path"], note)

            for line in proc.stdout:
                rec = json.loads(line)
                kind = rec["type"]
                if kind == "ipsw":
                    ipsw_id = rec["id"]
                    if not rescan and store.has_ipsw(conn, ipsw_id):
                        raise AlreadyScanned(f"IPSW {rec['name']} ({ipsw_id}) is already in the database")
                    store.save_ipsw(conn, rec)
                    log.info("scanning %s %s (%s) for %s",
                             rec["name"], rec["version"], rec["build"], ", ".join(rec.get("devices", [])))
                elif kind == "dsc":
                    store.save_dsc(conn, ipsw_id, rec)
                elif kind == "image":
                    flush()
                    image, symbols = rec, []
                elif kind == "symbol":
                    symbols.append((rec["start"], rec["end"], rec["name"]))
                # other record types (comparison facts) are not part of the symbol database
            flush()

            if proc.wait() != 0:
                stderr.seek(0)
                raise ScanFailed(stderr.read().strip()[-2000:] or f"ipsw exited with {proc.returncode}")
            conn.commit()
        except BaseException:
            conn.rollback()
            proc.kill()
            proc.wait()
            raise
        finally:
            conn.close()

    counts["seconds"] = round(time.time() - started, 1)
    log.info(
        "scan done in %ss: %d images, %d symbols, %d images already stored",
        counts["seconds"], counts["images"], counts["symbols"], counts["skipped"],
    )
    return counts
