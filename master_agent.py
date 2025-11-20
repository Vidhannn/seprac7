import os
import json
import time
import urllib.parse
import urllib3
import re
from typing import List, Dict, Any, Tuple, Optional
from enum import Enum
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
# Enums and Data Structures
# -------------------------
class ScanPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    DETECTION = "detection"
    EXPLOITATION = "exploitation"

class VulnerabilityType(Enum):
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    RCE = "rce"
    FILE_INCLUSION = "file_inclusion"
    DESERIALIZATION = "deserialization"
    UNKNOWN = "unknown"

class ParameterType(Enum):
    QUERY_STRING = "query_string"
    JSON_BODY = "json_body"
    FORM_DATA = "form_data"
    HEADER = "header"
    PATH_PARAM = "path_param"

class ParameterContext:
    def __init__(self, name: str, value: str, param_type: ParameterType, 
                 encoding: str = "plain", potential_sinks: List[str] = None):
        self.name = name
        self.value = value
        self.type = param_type
        self.encoding = encoding
        self.potential_sinks = potential_sinks or []
        self.vulnerability_scores = {vuln: 0.0 for vuln in VulnerabilityType}

class ScanState:
    def __init__(self):
        self.current_phase = ScanPhase.RECONNAISSANCE
        self.parameters: List[ParameterContext] = []
        self.vulnerability_decisions: Dict[VulnerabilityType, Dict[str, Any]] = {}
        self.global_payload_count = 0
        self.round_count = 0
        self.phase_history: List[Dict[str, Any]] = []

# -------------------------
# Parameter Context Analyzer
# -------------------------
class ParameterContextAnalyzer:
    """Analyzes HTTP requests to classify parameters and predict vulnerability types"""
    
    @staticmethod
    def detect_encoding(value: str) -> str:
        """Detect the encoding of a parameter value"""
        if not value:
            return "plain"
        
        # Check for URL encoding
        if '%' in value and re.search(r'%[0-9A-Fa-f]{2}', value):
            return "url"
        
        # Check for base64
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value) and len(value) % 4 == 0:
            return "base64"
        
        # Check for JSON
        if value.startswith('{') or value.startswith('['):
            return "json"
        
        # Check for XML
        if value.startswith('<') and value.endswith('>'):
            return "xml"
        
        return "plain"
    
    @staticmethod
    def classify_parameter_type(param_name: str, location: str) -> ParameterType:
        """Classify the type of parameter based on name and location"""
        if location == "header":
            return ParameterType.HEADER
        elif location == "path":
            return ParameterType.PATH_PARAM
        elif location == "body":
            # Try to determine if it's JSON or form data
            if param_name.startswith('[') or '.' in param_name:
                return ParameterType.JSON_BODY
            else:
                return ParameterType.FORM_DATA
        else:
            return ParameterType.QUERY_STRING
    
    @staticmethod
    def analyze_parameter_for_vulnerabilities(param_name: str, param_value: str, 
                                            param_type: ParameterType) -> Dict[VulnerabilityType, float]:
        """Analyze a parameter for potential vulnerability types"""
        scores = {vuln: 0.0 for vuln in VulnerabilityType}
        
        name_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Injection vulnerabilities
        injection_indicators = ['sql', 'query', 'search', 'filter', 'id', 'user', 'pass']
        if any(indicator in name_lower for indicator in injection_indicators):
            scores[VulnerabilityType.INJECTION] += 0.3
        
        # XSS indicators
        xss_indicators = ['comment', 'message', 'text', 'content', 'html', 'callback']
        if any(indicator in name_lower for indicator in xss_indicators):
            scores[VulnerabilityType.XSS] += 0.3
        
        # SSRF indicators
        ssrf_indicators = ['url', 'link', 'redirect', 'callback', 'webhook', 'proxy']
        if any(indicator in name_lower for indicator in ssrf_indicators):
            scores[VulnerabilityType.SSRF] += 0.4
        
        # File inclusion indicators
        file_indicators = ['file', 'path', 'dir', 'folder', 'include', 'template', 'view']
        if any(indicator in name_lower for indicator in file_indicators):
            scores[VulnerabilityType.FILE_INCLUSION] += 0.4
        
        # Deserialization indicators
        deser_indicators = ['data', 'object', 'serial', 'session', 'state']
        if any(indicator in name_lower for indicator in deser_indicators):
            scores[VulnerabilityType.DESERIALIZATION] += 0.3
        
        # RCE indicators (highest risk)
        rce_indicators = ['cmd', 'command', 'exec', 'run', 'eval', 'code', 'script']
        if any(indicator in name_lower for indicator in rce_indicators):
            scores[VulnerabilityType.RCE] += 0.5
        
        # Value-based analysis
        if 'http' in value_lower or 'https' in value_lower:
            scores[VulnerabilityType.SSRF] += 0.3
        
        if any(tech in value_lower for tech in ['<script', 'javascript:', 'onload', 'onerror']):
            scores[VulnerabilityType.XSS] += 0.4
        
        # Normalize scores
        for vuln in scores:
            scores[vuln] = min(scores[vuln], 1.0)
        
        return scores
    
    @classmethod
    def analyze_http_request(cls, parsed_request: Dict[str, Any]) -> List[ParameterContext]:
        """Analyze a parsed HTTP request and extract parameter contexts"""
        parameters = []
        
        # Analyze query string parameters
        url = parsed_request['url']
        if '?' in url:
            query_part = url.split('?', 1)[1]
            query_params = urllib.parse.parse_qs(query_part, keep_blank_values=True)
            
            for name, values in query_params.items():
                for value in values:
                    if '*run' in name or '*run' in value:
                        param_type = cls.classify_parameter_type(name, "query")
                        encoding = cls.detect_encoding(value)
                        vuln_scores = cls.analyze_parameter_for_vulnerabilities(name, value, param_type)
                        
                        context = ParameterContext(name, value, param_type, encoding)
                        context.vulnerability_scores = vuln_scores
                        parameters.append(context)
        
        # Analyze body parameters
        body = parsed_request.get('data', '')
        if body and ('*run' in body or any('*run' in param for param in re.findall(r'([^&=]+)=', body))):
            try:
                # Try JSON parsing first
                if body.strip().startswith('{') or body.strip().startswith('['):
                    json_data = json.loads(body)
                    json_params = cls._extract_json_params(json_data)
                    
                    for name, value in json_params:
                        if '*run' in name or '*run' in str(value):
                            param_type = ParameterType.JSON_BODY
                            encoding = cls.detect_encoding(str(value))
                            vuln_scores = cls.analyze_parameter_for_vulnerabilities(name, str(value), param_type)
                            
                            context = ParameterContext(name, str(value), param_type, encoding)
                            context.vulnerability_scores = vuln_scores
                            parameters.append(context)
                else:
                    # Form data parsing
                    form_params = urllib.parse.parse_qs(body, keep_blank_values=True)
                    
                    for name, values in form_params.items():
                        for value in values:
                            if '*run' in name or '*run' in value:
                                param_type = ParameterType.FORM_DATA
                                encoding = cls.detect_encoding(value)
                                vuln_scores = cls.analyze_parameter_for_vulnerabilities(name, value, param_type)
                                
                                context = ParameterContext(name, value, param_type, encoding)
                                context.vulnerability_scores = vuln_scores
                                parameters.append(context)
            except (json.JSONDecodeError, Exception):
                pass
        
        # Analyze headers
        headers = parsed_request.get('headers', {})
        for name, value in headers.items():
            if '*run' in name or '*run' in value:
                param_type = ParameterType.HEADER
                encoding = cls.detect_encoding(value)
                vuln_scores = cls.analyze_parameter_for_vulnerabilities(name, value, param_type)
                
                context = ParameterContext(name, value, param_type, encoding)
                context.vulnerability_scores = vuln_scores
                parameters.append(context)
        
        return parameters
    
    @staticmethod
    def _extract_json_params(data: Any, prefix: str = "") -> List[Tuple[str, Any]]:
        """Recursively extract parameters from JSON data"""
        params = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_prefix = f"{prefix}.{key}" if prefix else key
                params.extend(ParameterContextAnalyzer._extract_json_params(value, current_prefix))
        elif isinstance(data, list):
            for i, value in enumerate(data):
                current_prefix = f"{prefix}[{i}]" if prefix else f"[{i}]"
                params.extend(ParameterContextAnalyzer._extract_json_params(value, current_prefix))
        else:
            params.append((prefix, data))
        
        return params

# -------------------------
# Multi-Phase Scanner
# -------------------------
class MultiPhaseScanner:
    """Multi-phase vulnerability scanner with context-aware analysis"""
    
    def __init__(self, parsed_request: Dict[str, Any]):
        self.parsed_request = parsed_request
        self.state = ScanState()
        self.analyzer = ParameterContextAnalyzer()
        self.history: List[Dict[str, Any]] = []
        
        # Initialize parameters
        self.state.parameters = self.analyzer.analyze_http_request(parsed_request)
        
    def get_phase_prompt(self, phase: ScanPhase) -> str:
        """Get the appropriate system prompt for the current phase"""
        
        if phase == ScanPhase.RECONNAISSANCE:
            return (
                "You are an autonomous security testing agent in the RECONNAISSANCE phase. "
                "Your goal is to map parameters and identify potential vulnerability types.\n"
                "\n"
                "You will receive parameter context information and should design basic test payloads "
                "to identify how the application processes different inputs.\n"
                "\n"
                "=== Behavior Rules ===\n"
                "- Output ONLY the JSON object as specified in `STRICT OUTPUT FORMAT`.\n"
                "- Use safe, non-malicious test payloads to identify input processing behavior.\n"
                "- Max 25 payloads per round. No duplicates.\n"
                "- Focus on identifying parameter types, encodings, and potential sinks.\n"
                "=== Output Format ===\n"
                "{\n"
                "  \"next_payloads\": [\"...\"],\n"
                "  \"phase_analysis\": {\n"
                "      \"parameter_insights\": [\"insight1\", \"insight2\", ...],\n"
                "      \"suspected_vulnerabilities\": [\"vuln_type1\", \"vuln_type2\", ...],\n"
                "      \"recommended_next_phase\": \"detection\" | \"exploitation\" | \"continue_recon\"\n"
                "  },\n"
                "  \"final_decision\": {\n"
                "      \"status\": \"UNDECIDED\" | \"VULNERABLE\" | \"LIKELY_NOT_VULNERABLE\" | \"UNSURE\",\n"
                "      \"confidence\": <number between 0 and 1>,\n"
                "      \"summary\": \"short explanation based only on observed responses\",\n"
                "      \"key_evidence\": [\"point1\", \"point2\", ...],\n"
                "      \"poc_examples\": []\n"
                "  }\n"
                "}\n"
            )
        
        elif phase == ScanPhase.DETECTION:
            return (
                "You are an autonomous security testing agent in the DETECTION phase. "
                "Your goal is to confirm vulnerabilities using targeted payloads.\n"
                "\n"
                "Based on reconnaissance insights, design payloads that can definitively confirm "
                "or deny suspected vulnerability types. Focus on safe proof-of-concept payloads.\n"
                "\n"
                "=== Behavior Rules ===\n"
                "- Output ONLY the JSON object as specified in `STRICT OUTPUT FORMAT`.\n"
                "- Use targeted payloads for the suspected vulnerability types.\n"
                "- Max 25 payloads per round. No duplicates.\n"
                "- Avoid malicious payloads; focus on detection and confirmation.\n"
                "=== Output Format ===\n"
                "{\n"
                "  \"next_payloads\": [\"...\"],\n"
                "  \"phase_analysis\": {\n"
                "      \"confirmed_vulnerabilities\": [\"vuln_type1\", \"vuln_type2\", ...],\n"
                "      \"detection_confidence\": <number between 0 and 1>,\n"
                "      \"exploitation_potential\": \"low\" | \"medium\" | \"high\",\n"
                "      \"recommended_next_phase\": \"exploitation\" | \"continue_detection\" | \"complete\"\n"
                "  },\n"
                "  \"final_decision\": {\n"
                "      \"status\": \"UNDECIDED\" | \"VULNERABLE\" | \"LIKELY_NOT_VULNERABLE\" | \"UNSURE\",\n"
                "      \"confidence\": <number between 0 and 1>,\n"
                "      \"summary\": \"short explanation based only on observed responses\",\n"
                "      \"key_evidence\": [\"point1\", \"point2\", ...],\n"
                "      \"poc_examples\": [\n"
                "          {\n"
                "              \"payload\": \"exact payload string used\",\n"
                "              \"observation\": \"key behavior observed\",\n"
                "              \"reason\": \"why this proves or disproves the vulnerability.\"\n"
                "          }\n"
                "      ]\n"
                "  }\n"
                "}\n"
            )
        
        else:  # EXPLOITATION
            return (
                "You are an autonomous security testing agent in the EXPLOITATION phase. "
                "Your goal is to escalate confirmed vulnerabilities to demonstrate impact.\n"
                "\n"
                "ONLY proceed if detection confidence is high (>0.7). Design payloads that can "
                "demonstrate the full impact of confirmed vulnerabilities, potentially leading to RCE.\n"
                "\n"
                "=== Behavior Rules ===\n"
                "- Output ONLY the JSON object as specified in `STRICT OUTPUT FORMAT`.\n"
                "- Only attempt exploitation if detection confidence is high.\n"
                "- Max 25 payloads per round. No duplicates.\n"
                "- Focus on demonstrating impact while maintaining safety boundaries.\n"
                "=== Output Format ===\n"
                "{\n"
                "  \"next_payloads\": [\"...\"],\n"
                "  \"phase_analysis\": {\n"
                "      \"exploitation_success\": boolean,\n"
                "      \"impact_level\": \"low\" | \"medium\" | \"high\" | \"critical\",\n"
                "      \"rce_achieved\": boolean,\n"
                "      \"recommended_next_phase\": \"complete\" | \"continue_exploitation\"\n"
                "  },\n"
                "  \"final_decision\": {\n"
                "      \"status\": \"UNDECIDED\" | \"VULNERABLE\" | \"LIKELY_NOT_VULNERABLE\" | \"UNSURE\",\n"
                "      \"confidence\": <number between 0 and 1>,\n"
                "      \"summary\": \"short explanation based only on observed responses\",\n"
                "      \"key_evidence\": [\"point1\", \"point2\", ...],\n"
                "      \"poc_examples\": [\n"
                "          {\n"
                "              \"payload\": \"exact payload string used\",\n"
                "              \"observation\": \"key behavior observed\",\n"
                "              \"reason\": \"why this demonstrates exploitation.\"\n"
                "          }\n"
                "      ]\n"
                "  }\n"
                "}\n"
            )
    
    def build_context_metadata(self) -> Dict[str, Any]:
        """Build structured metadata from parameter context analysis"""
        metadata = {
            "total_parameters": len(self.state.parameters),
            "parameter_details": [],
            "suspected_vulnerabilities": [],
            "encoding_distribution": {},
            "parameter_type_distribution": {}
        }
        
        for param in self.state.parameters:
            param_detail = {
                "name": param.name,
                "type": param.type.value,
                "encoding": param.encoding,
                "vulnerability_scores": {vuln.value: score for vuln, score in param.vulnerability_scores.items()},
                "top_vulnerability": max(param.vulnerability_scores.items(), key=lambda x: x[1])[0].value
            }
            metadata["parameter_details"].append(param_detail)
            
            # Track suspected vulnerabilities
            top_vuln, top_score = max(param.vulnerability_scores.items(), key=lambda x: x[1])
            if top_score > 0.3:
                metadata["suspected_vulnerabilities"].append(top_vuln.value)
            
            # Track distributions
            metadata["encoding_distribution"][param.encoding] = metadata["encoding_distribution"].get(param.encoding, 0) + 1
            metadata["parameter_type_distribution"][param.type.value] = metadata["parameter_type_distribution"].get(param.type.value, 0) + 1
        
        return metadata
    
    def should_transition_phase(self, llm_response: Dict[str, Any]) -> Optional[ScanPhase]:
        """Determine if we should transition to the next phase"""
        phase_analysis = llm_response.get("phase_analysis", {})
        
        if self.state.current_phase == ScanPhase.RECONNAISSANCE:
            next_phase = phase_analysis.get("recommended_next_phase", "continue_recon")
            if next_phase == "detection":
                return ScanPhase.DETECTION
            elif next_phase == "exploitation":
                return ScanPhase.EXPLOITATION
        
        elif self.state.current_phase == ScanPhase.DETECTION:
            next_phase = phase_analysis.get("recommended_next_phase", "continue_detection")
            if next_phase == "exploitation":
                detection_confidence = phase_analysis.get("detection_confidence", 0.0)
                if detection_confidence > 0.7:
                    return ScanPhase.EXPLOITATION
            elif next_phase == "complete":
                return None
        
        elif self.state.current_phase == ScanPhase.EXPLOITATION:
            next_phase = phase_analysis.get("recommended_next_phase", "continue_exploitation")
            if next_phase == "complete":
                return None
        
        return self.state.current_phase
    
    def send_payload_to_parameter(self, param: ParameterContext, payload: str) -> Dict[str, Any]:
        """Send a payload to a specific parameter"""
        # Create a copy of the parsed request
        request_copy = self.parsed_request.copy()
        
        # Replace the *run placeholder in the appropriate location
        if param.type == ParameterType.QUERY_STRING:
            request_copy["url"] = request_copy["url"].replace(f"*run", urllib.parse.quote(payload, safe=""))
        elif param.type == ParameterType.JSON_BODY:
            request_copy["data"] = request_copy["data"].replace(f"*run", payload)
        elif param.type == ParameterType.FORM_DATA:
            request_copy["data"] = request_copy["data"].replace(f"*run", urllib.parse.quote(payload, safe=""))
        elif param.type == ParameterType.HEADER:
            for header_name in request_copy["headers"]:
                if "*run" in request_copy["headers"][header_name]:
                    request_copy["headers"][header_name] = request_copy["headers"][header_name].replace("*run", payload)
        
        return send_with_run(request_copy, payload)
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute the multi-phase scan"""
        print(f"[*] Starting multi-phase scan with {len(self.state.parameters)} parameters")
        
        # Build initial context metadata
        context_metadata = self.build_context_metadata()
        print(f"[*] Parameter analysis complete: {context_metadata['total_parameters']} parameters found")
        print(f"[*] Suspected vulnerabilities: {list(set(context_metadata['suspected_vulnerabilities']))}")
        
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": self.get_phase_prompt(self.state.current_phase)},
            {
                "role": "user",
                "content": f"PARAMETER_CONTEXT:\n{json.dumps(context_metadata, indent=2)}\n\n"
                          f"HISTORY:\n(none yet)\n\nNow respond ONLY with the JSON object as per the specified format."
            },
        ]
        
        total_payloads_sent = 0
        final_decision: Dict[str, Any] = {}
        
        for phase in [ScanPhase.RECONNAISSANCE, ScanPhase.DETECTION, ScanPhase.EXPLOITATION]:
            if self.state.current_phase != phase:
                continue
                
            print(f"[*] Starting {phase.value.upper()} phase...")
            
            for round_idx in range(1, MAX_ROUNDS + 1):
                if self.state.current_phase != phase:
                    break
                    
                print(f"[*] {phase.value.upper()} Phase - Round {round_idx}: requesting payloads from LLM...")
                
                llm_json = call_llm(messages)
                
                next_payloads = llm_json.get("next_payloads") or []
                decision = llm_json.get("final_decision") or {}
                phase_analysis = llm_json.get("phase_analysis", {})
                
                status = str(decision.get("status", "UNDECIDED")).upper()
                confidence = float(decision.get("confidence", 0.0) or 0.0)
                summary = decision.get("summary", "") or ""
                key_evidence = decision.get("key_evidence") or []
                poc_examples = decision.get("poc_examples") or []
                
                # Check for phase transition
                next_phase = self.should_transition_phase(llm_json)
                if next_phase != self.state.current_phase:
                    if next_phase is None:
                        print(f"[*] Scan complete - {phase.value.upper()} phase recommends completion")
                        final_decision = decision
                        break
                    else:
                        print(f"[*] Transitioning from {phase.value.upper()} to {next_phase.value.upper()}")
                        self.state.current_phase = next_phase
                        messages = [
                            {"role": "system", "content": self.get_phase_prompt(next_phase)},
                            {
                                "role": "user",
                                "content": f"PARAMETER_CONTEXT:\n{json.dumps(context_metadata, indent=2)}\n\n"
                                          f"PREVIOUS_PHASE_SUMMARY:\n{json.dumps(phase_analysis, indent=2)}\n\n"
                                          f"HISTORY:\n(none yet in this phase)\n\nNow respond ONLY with the JSON object as per the specified format."
                            },
                        ]
                        break
                
                # Stop if LLM is confident
                if status in ("VULNERABLE", "LIKELY_NOT_VULNERABLE", "UNSURE") and confidence > 0:
                    final_decision = {
                        "status": status,
                        "confidence": confidence,
                        "summary": summary,
                        "key_evidence": key_evidence,
                        "poc_examples": poc_examples,
                        "phase_completed": phase.value,
                        "phase_analysis": phase_analysis
                    }
                    print(f"[*] LLM returned a final decision in {phase.value.upper()} phase; stopping.")
                    break
                
                # Clean/limit payloads
                clean_payloads = []
                seen = set()
                for p in next_payloads:
                    if not isinstance(p, str):
                        continue
                    p = p.strip()
                    if not p or p in seen or len(p) > 400:
                        continue
                    clean_payloads.append(p)
                    seen.add(p)
                    if len(clean_payloads) >= MAX_PAYLOADS_PER_ROUND:
                        break
                
                if not clean_payloads:
                    final_decision = {
                        "status": "UNSURE",
                        "confidence": 0.3,
                        "summary": f"Model did not provide usable payloads in {phase.value.upper()} phase.",
                        "key_evidence": [],
                        "poc_examples": [],
                        "phase_completed": phase.value
                    }
                    break
                
                remaining = MAX_TOTAL_PAYLOADS - total_payloads_sent
                if remaining <= 0:
                    final_decision = {
                        "status": "UNSURE",
                        "confidence": 0.4,
                        "summary": "Reached global payload cap without conclusive decision.",
                        "key_evidence": [],
                        "poc_examples": [],
                        "phase_completed": phase.value
                    }
                    break
                
                if len(clean_payloads) > remaining:
                    clean_payloads = clean_payloads[:remaining]
                
                # Send payloads
                for payload in clean_payloads:
                    # Send to the most promising parameter for this phase
                    target_param = self.select_target_parameter(phase)
                    if not target_param:
                        break
                        
                    res = self.send_payload_to_parameter(target_param, payload)
                    total_payloads_sent += 1
                    self.state.global_payload_count += 1
                    
                    body = res["body"]
                    if isinstance(body, (dict, list)):
                        body_str = json.dumps(body) or "{'None': 'No body returned'}"
                    else:
                        body_str = str(body) or "{'None': 'No body returned'}"
                    body_str = body_str.replace("\n", " ")[:400]
                    
                    self.history.append({
                        "payload": payload,
                        "parameter": target_param.name,
                        "phase": phase.value,
                        "status": res["status"],
                        "body_snippet": body_str,
                        "elapsed_ms": int(res.get("elapsed", 0.0) * 1000)
                    })
                    
                    time.sleep(SLEEP_BETWEEN_REQUESTS)
                
                # Prepare HISTORY feed for LLM
                last_entries = self.history[-80:]
                history_lines = [
                    f"- payload: {h['payload']} | param: {h['parameter']} | phase: {h['phase']} | status: {h['status']} | time_ms: {h['elapsed_ms']} | body: {h['body_snippet']}"
                    for h in last_entries
                ]
                history_text = "HISTORY:\n" + "\n".join(history_lines)
                
                # Feed back to LLM
                messages.append({"role": "assistant", "content": json.dumps(llm_json)})
                messages.append({
                    "role": "user",
                    "content": f"{history_text}\n\nBased on this HISTORY, update your analysis and respond ONLY with the JSON object."
                })
            
            # Check if we should continue to next phase
            if final_decision and final_decision.get("status") in ["VULNERABLE", "LIKELY_NOT_VULNERABLE"]:
                break
        
        # Fallback if no final decision
        if not final_decision:
            final_decision = {
                "status": "UNSURE",
                "confidence": 0.3,
                "summary": "Max rounds reached without a conclusive final decision from the model.",
                "key_evidence": [],
                "poc_examples": [],
                "phase_completed": self.state.current_phase.value
            }
        
        # Add scan metadata to final decision
        final_decision.update({
            "scan_metadata": {
                "total_parameters": len(self.state.parameters),
                "phases_completed": [p.value for p in [ScanPhase.RECONNAISSANCE, ScanPhase.DETECTION, ScanPhase.EXPLOITATION] if p.value in [h.get('phase') for h in self.history]],
                "total_payloads_sent": total_payloads_sent,
                "parameter_analysis": context_metadata
            }
        })
        
        return final_decision
    
    def select_target_parameter(self, phase: ScanPhase) -> Optional[ParameterContext]:
        """Select the best target parameter for the current phase"""
        if not self.state.parameters:
            return None
        
        if phase == ScanPhase.RECONNAISSANCE:
            # In recon, prioritize parameters with highest vulnerability diversity
            return max(self.state.parameters, key=lambda p: len([v for v in p.vulnerability_scores.values() if v > 0.3]))
        
        elif phase == ScanPhase.DETECTION:
            # In detection, prioritize parameters with highest single vulnerability score
            return max(self.state.parameters, key=lambda p: max(p.vulnerability_scores.values()))
        
        elif phase == ScanPhase.EXPLOITATION:
            # In exploitation, prioritize RCE or high-impact vulnerabilities
            rce_params = [p for p in self.state.parameters if p.vulnerability_scores.get(VulnerabilityType.RCE, 0) > 0.5]
            if rce_params:
                return max(rce_params, key=lambda p: p.vulnerability_scores.get(VulnerabilityType.RCE, 0))
            
            # Fallback to highest scoring parameter
            return max(self.state.parameters, key=lambda p: max(p.vulnerability_scores.values()))
        
        return self.state.parameters[0]

# -------------------------
# Helper Functions (Legacy)
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
    Sends HTTP request safely, replacing *run placeholder with the expression.
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
# LLM Functions (Legacy)
# -------------------------
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
        "X-Title": "Multi-Phase Autonomous Vulnerability Scanner",
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
# Core Autonomous Scan Function (Refactored)
# -------------------------
def run_autonomous_scan(http_request: str):
    """
    Refactored multi-phase autonomous vulnerability scanner.
    Replaces SpEL-specific logic with generic vulnerability detection.
    """
    try:
        parsed = parse_http_request(http_request)
        scanner = MultiPhaseScanner(parsed)
        result = scanner.run_scan()
        
        # Print structured result
        status = result.get("status", "UNSURE")
        confidence = float(result.get("confidence", 0.0))
        summary = result.get("summary", "") or ""
        key_evidence = result.get("key_evidence") or []
        poc_examples = result.get("poc_examples") or []
        scan_metadata = result.get("scan_metadata", {})
        
        print("\n================ Multi-Phase Autonomous Scan Result ================")
        print(f"Decision      : {status}")
        print(f"Confidence    : {confidence:.2f}")
        print(f"Phase Completed: {result.get('phase_completed', 'N/A')}")
        print(f"Total Parameters: {scan_metadata.get('total_parameters', 0)}")
        print(f"Total Payloads: {scan_metadata.get('total_payloads_sent', 0)}")
        print("-------------------------------------------------------------")
        
        if summary:
            print("Summary:")
            print(f"  - {summary}")
        
        if scan_metadata.get("parameter_analysis"):
            param_analysis = scan_metadata["parameter_analysis"]
            print(f"\nParameter Analysis:")
            print(f"  - Suspected vulnerabilities: {list(set(param_analysis.get('suspected_vulnerabilities', [])))}")
            print(f"  - Encoding types: {list(param_analysis.get('encoding_distribution', {}).keys())}")
            print(f"  - Parameter types: {list(param_analysis.get('parameter_type_distribution', {}).keys())}")
        
        if key_evidence:
            print("\nKey Evidence (from model):")
            for ev in key_evidence[:12]:
                print(f"  - {ev}")
        else:
            print("\nKey Evidence:")
            print("  - (none reported by model)")

        print("\nPoC Details:")
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

        print("=================================================================\n")

        return result
        
    except Exception as e:
        print(f"[X] Multi-phase scan failed: {e}")
        return {
            "status": "ERROR",
            "confidence": 0.0,
            "summary": f"Scan failed with error: {str(e)}",
            "key_evidence": [],
            "poc_examples": []
        }


# -------------------------
# CLI for File-based Input (Backward Compatible)
# -------------------------
def main():
    print("=== Multi-Phase Autonomous Vulnerability Scanner (LLM-driven) ===")
    file_path = input("Enter the path to the HTTP request file containing *run:\n> ").strip()

    if not os.path.exists(file_path):
        print(f"[X] File not found: {file_path}")
        return

    print("\n[+] Load and scan from file:", file_path)

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