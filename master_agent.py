import os
import json
import time
import urllib.parse
import urllib3
from typing import List, Dict, Any
import requests
from dotenv import load_dotenv

# -------------------------
# Suppress SSL InsecureRequestWarning
# -------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Configuration
# -------------------------
load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    raise EnvironmentError("OPENROUTER_API_KEY missing in environment or .env")

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "minimax/minimax-m2"

REQUEST_TIMEOUT = 15
LLM_TIMEOUT = 90

MAX_ROUNDS = 6
MAX_PAYLOADS_PER_ROUND = 25
MAX_TOTAL_PAYLOADS = 150
SLEEP_BETWEEN_REQUESTS = 0.12

# -------------------------
# Helper Functions
# -------------------------
def parse_http_request(http_request: str) -> Dict[str, Any]:
    """
    Parses a raw HTTP request (from a .txt file) into a dictionary.
    The placeholder *run is expected to be in the query string or the payload.
    """
    lines = http_request.strip().splitlines()
    if not lines:
        raise ValueError("Empty HTTP request in file.")

    request_line = lines[0].strip()
    if not request_line:
        raise ValueError("Could not parse request line.")
    if request_line.startswith("HTTP/"):
        raise ValueError("Input is a response, not a request.")

    parts = request_line.split(" ", 2)
    if len(parts) < 3:
        raise ValueError("Invalid request line format: expected method, path, and HTTP version.")
    method, path, http_version = parts

    headers = {}
    body = ""
    host = None
    current_line = 1
    while current_line < len(lines):
        line = lines[current_line].strip()
        if not line:
            if method in ["POST", "PUT", "PATCH", "DELETE"]:
                # Body starts after the empty line
                body_lines = lines[current_line + 1:]
                body = "\n".join(body_lines)
            break
        if line.startswith("Host:"):
            host = line.split("Host:", 1)[1].strip()
        else:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        current_line += 1

    if not host:
        raise ValueError("Host header not found in the HTTP request.")

    # Construct the complete URL
    full_url = path if path.startswith("http") else f"https://{host}{path}"

    # Ensure *run is present
    if "*run" not in full_url and (method in ["POST", "PUT", "PATCH", "DELETE"] and "*run" not in body):
        raise ValueError(f"Input must contain the *run placeholder in URL or body, but it was not found.")

    return {
        "method": method.upper(),
        "url": full_url,
        "headers": headers,
        "data": body
    }


def send_with_run(parsed: Dict[str, Any], expr: str) -> Dict[str, Any]:
    """
    Sends HTTP request safely, replacing *run placeholder with the SpEL expression.
    Configures `verify=False` to suppress SSL certificate warnings.
    """
    # Replace the *run placeholder with the quoted expression
    encoded = urllib.parse.quote(expr, safe="")
    url = parsed["url"].replace("*run", encoded)

    # Replace *run in data if it's a POST/PUT/PATCH/DELETE request
    if parsed["method"] in ["POST", "PUT", "PATCH", "DELETE"] and parsed.get("data"):
        parsed["data"] = parsed["data"].replace("*run", encoded)

    # Proxy support
    proxies = {
        "http": os.getenv("HTTP_PROXY"),
        "https": os.getenv("HTTPS_PROXY"),
    }

    # SSL verification flag
    ssl_verify = os.getenv("SSL_VERIFY", "False").lower() == "true"

    start = time.time()
    try:
        response = requests.request(
            method=parsed["method"],
            url=url,
            headers=parsed.get("headers", {}),
            data=parsed.get("data"),
            proxies=proxies,
            verify=ssl_verify,
            timeout=REQUEST_TIMEOUT
        )
        elapsed = time.time() - start
        try:
            body = response.json()
        except Exception:
            body = response.text
        return {
            "status": response.status_code,
            "body": body,
            "url": url,
            "elapsed": elapsed,
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "status": None,
            "body": str(e),
            "url": url,
            "elapsed": elapsed,
        }


# -------------------------
# LLM Prompt Definition
# -------------------------
SYSTEM_PROMPT = (
    "You are an autonomous security testing agent focused strictly on detecting Spring Expression Language (SpEL) "
    "injection vulnerabilities in a single HTTP parameter.\n"
    "\n"
    "You operate in iterative rounds. In each round, you receive a HISTORY section showing payloads you requested and "
    "their HTTP responses (status, truncated body, and response time).\n"
    "\n"
    "Your goals:\n"
    "- Design SpEL-style expressions that can:\n"
    "  * Distinguish between literal interpretation and SpEL evaluation,\n"
    "  * Confirm or refute SpEL evaluation behavior,\n"
    "  * If confirmed, produce a SAFE PoC payload, exposing how the input is evaluated.\n"
    "\n"
    "Safe PoC expectations (mandatory when declaring `VULNERABLE`):\n"
    "- Must not use runtime.getRuntime(), exec(), system(), etc. (no OS execution).\n"
    "- Can use expression-based patterns like:\n"
    "  * True/false/boolean results affecting response (status/body)\n"
    "  * Arithmetic or string expressions returning computed results instead of literals\n"
    "  * Class access via T(java.lang.String) or method calls (e.g., T(java.lang.Thread).sleep(1000))\n"
    "  * Optionally, timing-based PoC with measurable delays (via SpEL/Java constructs)\n"
    "\n"
    "=== Behavior Rules ===\n"
    "- Output ONLY the JSON object as specified in `STRICT OUTPUT FORMAT`.\n"
    "- Use only the `*run` placeholder and target ONLY that parameter.\n"
    "- Do not falsify results; base them only on the received server responses.\n"
    "- Max 25 payloads per round. No duplicates. Payloads must be syntactically valid SpEL expressions.\n"
    "- Once `VULNERABLE/LIKELY_NOT_VULNERABLE` is confirmed, stop scanning unless told otherwise.\n"
    "=== Output Format ===\n"
    "{\n"
    "  \"next_payloads\": [\"...\"],\n"
    "  \"final_decision\": {\n"
    "      \"status\": \"UNDECIDED\" | \"VULNERABLE\" | \"LIKELY_NOT_VULNERABLE\" | \"UNSURE\",\n"
    "      \"confidence\": <number between 0 and 1>,\n"
    "      \"summary\": \"short explanation based only on observed responses\",\n"
    "      \"key_evidence\": [\"point1\", \"point2\", ...],\n"
    "      \"poc_examples\": [\n"
    "          {\n"
    "              \"payload\": \"exact payload string used\",\n"
    "              \"observation\": \"key behavior observed\",\n"
    "              \"reason\": \"why this proves or disproves SpEL evaluation.\"\n"
    "          }\n"
    "      ]\n"
    "  }\n"
    "}\n"
)


def safe_json_parse(content: str) -> Dict[str, Any]:
    """
    Helps parse the model's returned JSON even if it's malformed.
    """
    content = content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        if start == -1:
            return {}
        end = content.rfind("}")
        if end == -1 or end <= start:
            return {}
        snippet = content[start:end+1]
        try:
            return json.loads(snippet)
        except Exception:
            return {}


def call_llm(messages: List[Dict[str, str]], max_tokens=900) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY.strip()}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://your-site.com",
        "X-Title": "Autonomous SpEL Injection Scanner",
    }

    payload = {
        "model": MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
    }

    last_error = None

    for attempt in range(1, 4):
        try:
            r = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=LLM_TIMEOUT,
            )
            if r.status_code >= 500:
                print(f"[!] LLM server error {r.status_code} (attempt {attempt}/3), retrying in 5s...")
                time.sleep(5)
                last_error = Exception(f"Server error {r.status_code}")
                continue

            r.raise_for_status()
            data = r.json()
            msg = data.get("choices", [{}])[0].get("message", {})
            content = (msg.get("content") or msg.get("reasoning") or "").strip()
            if not content:
                raise ValueError("Empty response from LLM")
            return safe_json_parse(content)

        except Exception as e:
            print(f"[!] LLM call/parse failed (attempt {attempt}/3): {e}")
            last_error = e
            time.sleep(5)

    raise RuntimeError(f"LLM API failure after {attempt} attempts: {last_error}")


# -------------------------
# Core Autonomous Scan Loop
# -------------------------
def run_autonomous_scan(http_request: str):
    parsed = parse_http_request(http_request)

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "HISTORY:\n(none yet)\n\nNow respond ONLY with the JSON object as per the specified format."
        },
    ]

    history: List[Dict[str, Any]] = []
    total_payloads_sent = 0
    final_decision: Dict[str, Any] = {}

    for round_idx in range(1, MAX_ROUNDS + 1):
        print(f"[*] Round {round_idx}: requesting next payloads from LLM...")

        llm_json = call_llm(messages)

        next_payloads = llm_json.get("next_payloads") or []
        decision = llm_json.get("final_decision") or {}

        status = str(decision.get("status", "UNDECIDED")).upper()
        confidence = float(decision.get("confidence", 0.0) or 0.0)
        summary = decision.get("summary", "") or ""
        key_evidence = decision.get("key_evidence") or []
        poc_examples = decision.get("poc_examples") or []

        # Stop if LLM is confident
        if status in ("VULNERABLE", "LIKELY_NOT_VULNERABLE", "UNSURE") and confidence > 0:
            final_decision = {
                "status": status,
                "confidence": confidence,
                "summary": summary,
                "key_evidence": key_evidence,
                "poc_examples": poc_examples,
            }
            print("[*] LLM returned a final decision; stopping further rounds.")
            break

        # Clean/limit payloads
        clean_payloads = []
        seen = set()
        for p in next_payloads:
            if not isinstance(p, str):
                continue
            p = p.strip()
            if not p:
                continue
            if p in seen:
                continue
            if len(p) > 400:
                continue
            low = p.lower()

            # Block unsafe payload types
            if any(bad in low for bad in [
                "runtime.getruntime",
                "exec(",
                "system(",
                "processbuilder",
                "scriptengine",
                "java.lang.runtime"
            ]):
                continue

            clean_payloads.append(p)
            seen.add(p)
            if len(clean_payloads) >= MAX_PAYLOADS_PER_ROUND:
                break

        if not clean_payloads:
            final_decision = {
                "status": "UNSURE",
                "confidence": 0.3,
                "summary": "Model did not provide usable payloads while undecided.",
                "key_evidence": [],
                "poc_examples": []
            }
            break

        remaining = MAX_TOTAL_PAYLOADS - total_payloads_sent
        if remaining <= 0:
            final_decision = {
                "status": "UNSURE",
                "confidence": 0.4,
                "summary": "Reached global payload cap without conclusive decision.",
                "key_evidence": [],
                "poc_examples": []
            }
            break

        if len(clean_payloads) > remaining:
            clean_payloads = clean_payloads[:remaining]

        # Send payloads
        for payload in clean_payloads:
            res = send_with_run(parsed, payload)
            total_payloads_sent += 1

            body = res["body"]
            if isinstance(body, (dict, list)):
                body_str = json.dumps(body) or "{'None': 'No body returned'}"
            else:
                body_str = str(body) or "{'None': 'No body returned'}"
            body_str = body_str.replace("\n", " ")[:400]

            history.append({
                "payload": payload,
                "status": res["status"],
                "body_snippet": body_str,
                "elapsed_ms": int(res.get("elapsed", 0.0) * 1000)
            })

            time.sleep(SLEEP_BETWEEN_REQUESTS)

        # Prepare HISTORY feed for LLM
        last_entries = history[-80:]
        history_lines = [
            f"- payload: {h['payload']} | status: {h['status']} | time_ms: {h['elapsed_ms']} | body: {h['body_snippet']}"
            for h in last_entries
        ]
        history_text = "HISTORY:\n" + "\n".join(history_lines)

        # Feed back to LLM
        messages.append({"role": "assistant", "content": json.dumps(llm_json)})
        messages.append({
            "role": "user",
            "content": f"{history_text}\n\nBased on this HISTORY, update your analysis and respond ONLY with the JSON object."
        })

    # Fallback if no final decision
    if not final_decision:
        final_decision = {
            "status": "UNSURE",
            "confidence": 0.3,
            "summary": "Max rounds reached without a conclusive final decision from the model.",
            "key_evidence": [],
            "poc_examples": []
        }

    # Derive PoC examples if not provided by LLM
    if final_decision.get("status") == "VULNERABLE" and not final_decision.get("poc_examples"):
        derived = []
        for h in history:
            body_low = h["body_snippet"].lower()
            if "spel" in body_low or "el100" in body_low or "el104" in body_low:
                derived.append({
                    "payload": h["payload"],
                    "observation": f"status={h['status']}, time_ms={h['elapsed_ms']}, body={h['body_snippet']}",
                    "reason": "SpEL/EL error indicates the parameter is interpreted as an expression."
                })
            elif h["body_snippet"].strip().lower() in ("true", "false"):
                derived.append({
                    "payload": h["payload"],
                    "observation": f"status={h['status']}, body={h['body_snippet']}",
                    "reason": "Boolean response confirms evaluation of the *run parameter."
                })
            if len(derived) >= 5:
                break
        final_decision["poc_examples"] = derived

    # Print structured result
    status = final_decision.get("status", "UNSURE")
    confidence = float(final_decision.get("confidence", 0.0))
    summary = final_decision.get("summary", "") or ""
    key_evidence = final_decision.get("key_evidence") or []
    poc_examples = final_decision.get("poc_examples") or []

    print("\n================ Autonomous SpEL Scan Result ================")
    print(f"Decision      : {status}")
    print(f"Confidence    : {confidence:.2f}")
    print(f"Total Payloads: {total_payloads_sent}")
    print("-------------------------------------------------------------")
    if summary:
        print("Summary:")
        print(f"  - {summary}")
    if key_evidence:
        print("\nKey Evidence (from model):")
        for ev in key_evidence[:12]:
            print(f"  - {ev}")
    else:
        print("\nKey Evidence:")
        print("  - (none reported by model)")

    print("\nPoC Details (safe, as reported/derived):")
    if poc_examples:
        for ex in poc_examples[:10]:
            payload = (ex.get("payload") or "").strip()
            obs = (ex.get("observation") or "").strip()
            reason = (ex.get("reason") or "").strip()
            if not payload:
                continue
            print("\n--- PoC Example ---")
            print(f"Payload    : {payload}")
            if obs:
                print(f"Observation: {obs}")
            if reason:
                print(f"Reason     : {reason}")
    else:
        print("  - No explicit PoC examples available, but decision is based on the evidence above.")

    print("=============================================================\n")

    return final_decision


# -------------------------
# CLI for File-based Input
# -------------------------
def main():
    print("=== Autonomous SpEL Injection Scanner (LLM-driven, safe PoC) ===")
    file_path = input("Enter the path to the HTTP request file containing *run:\n> ").strip()

    if not os.path.exists(file_path):
        print(f"[X] File not found: {file_path}")
        return

    print("\n[+] Load and send scan from file:", file_path)

    try:
        with open(file_path, "r") as f:
            http_request = f.read()
        run_autonomous_scan(http_request)
    except KeyboardInterrupt:
        print("\n[!] User interrupted. Exiting safely...", flush=True)
    except Exception as e:
        print(f"[X] Scan failed: {e}")


if __name__ == "__main__":
    main()
