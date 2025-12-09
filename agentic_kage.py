"""
Agentic Kage - AI-Powered Autonomous Port Scanner
==================================================
Extension for LivingArchive-clean that enables agentic AI decision-making.

Uses LivingArchive-clean's LLM Gateway for:
- Autonomous target prioritization
- Intelligent scan strategy generation
- Result analysis and next-action decisions
- Context-aware reconnaissance planning
"""
import asyncio
import json
import logging
import os
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgenticDecision:
    """AI-generated decision for autonomous operation"""
    action: str  # "scan", "deep_scan", "skip", "pause", "prioritize"
    reasoning: str
    confidence: float
    parameters: Dict[str, Any]
    next_steps: List[str]


@dataclass
class PrioritizedTarget:
    """AI-prioritized target for scanning"""
    target: Dict[str, Any]
    priority_score: float
    reasoning: str
    recommended_strategy: Dict[str, Any]


class AgenticKageExtension:
    """
    Agentic AI extension for Kage using LivingArchive-clean LLM Gateway.
    
    Enables autonomous decision-making for:
    - Target prioritization
    - Scan strategy generation
    - Result analysis
    - Next-action decisions
    """
    
    def __init__(self, llm_gateway_url: str = "http://localhost:8082", api_key: Optional[str] = None):
        """
        Initialize agentic Kage extension.
        
        Args:
            llm_gateway_url: LivingArchive-clean gateway URL
            api_key: Optional API key for authentication
        """
        self.llm_gateway_url = llm_gateway_url.rstrip('/')
        self.api_key = api_key or os.getenv('EGOLLAMA_API_KEY')
        self.enabled = True
        
        # Verify connection
        self._verify_connection()
    
    def _verify_connection(self):
        """Verify connection to LivingArchive-clean gateway"""
        try:
            response = requests.get(f"{self.llm_gateway_url}/health", timeout=5)
            if response.status_code == 200:
                logger.info(f"✅ Connected to LivingArchive-clean at {self.llm_gateway_url}")
                self.enabled = True
            else:
                logger.warning(f"⚠️ LivingArchive-clean gateway returned {response.status_code}")
                self.enabled = False
        except Exception as e:
            logger.warning(f"⚠️ Cannot connect to LivingArchive-clean: {e}")
            logger.info("   Agentic AI features will be disabled. Start LivingArchive-clean to enable.")
            self.enabled = False
    
    def _call_llm(self, prompt: str, max_tokens: int = 500, temperature: float = 0.7) -> Optional[str]:
        """Call LivingArchive-clean LLM Gateway"""
        if not self.enabled:
            return None
        
        try:
            url = f"{self.llm_gateway_url}/generate"
            headers = {
                "Content-Type": "application/json"
            }
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            
            data = {
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('text', result.get('response', ''))
            else:
                logger.error(f"LLM Gateway error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error calling LLM Gateway: {e}")
            return None
    
    def prioritize_targets(self, targets: List[Dict[str, Any]], context: Optional[Dict] = None) -> List[PrioritizedTarget]:
        """
        Use AI to prioritize targets for scanning.
        
        Args:
            targets: List of target dictionaries
            context: Optional context (previous scans, business value, etc.)
            
        Returns:
            List of prioritized targets with AI reasoning
        """
        if not self.enabled or not targets:
            # Fallback: return targets as-is
            return [PrioritizedTarget(t, 0.5, "AI unavailable - using default priority", {}) for t in targets]
        
        prompt = f"""As an expert cybersecurity reconnaissance agent, analyze and prioritize these {len(targets)} targets for port scanning.

Targets:
{json.dumps(targets, indent=2)}

Context:
{json.dumps(context or {}, indent=2)}

Consider:
1. Domain patterns and subdomain structure
2. Previous scan history and results
3. Business value indicators
4. Risk level and exposure
5. Scanning efficiency (group similar targets)

For each target, provide:
- priority_score: 0.0-1.0 (higher = scan first)
- reasoning: Why this priority
- recommended_strategy: Initial scan approach

Return JSON array:
[
  {{
    "target": {{original target data}},
    "priority_score": 0.85,
    "reasoning": "High-value subdomain with no recent scans",
    "recommended_strategy": {{"ports": [80, 443, 8080], "stealth": true}}
  }},
  ...
]

Return ONLY valid JSON, no markdown, no explanations."""
        
        response = self._call_llm(prompt, max_tokens=1000)
        
        if not response:
            # Fallback
            return [PrioritizedTarget(t, 0.5, "AI unavailable", {}) for t in targets]
        
        try:
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith('```'):
                # Remove markdown code blocks
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
                response = response.strip()
            
            prioritized_data = json.loads(response)
            
            results = []
            for item in prioritized_data:
                results.append(PrioritizedTarget(
                    target=item.get('target', {}),
                    priority_score=float(item.get('priority_score', 0.5)),
                    reasoning=item.get('reasoning', 'No reasoning provided'),
                    recommended_strategy=item.get('recommended_strategy', {})
                ))
            
            # Sort by priority score (highest first)
            results.sort(key=lambda x: x.priority_score, reverse=True)
            
            logger.info(f"✅ AI prioritized {len(results)} targets")
            return results
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}")
            logger.debug(f"Response was: {response[:200]}")
            # Fallback
            return [PrioritizedTarget(t, 0.5, "AI parsing failed", {}) for t in targets]
        except Exception as e:
            logger.error(f"Error in prioritize_targets: {e}", exc_info=True)
            return [PrioritizedTarget(t, 0.5, f"Error: {e}", {}) for t in targets]
    
    def generate_scan_strategy(self, target: str, target_info: Dict[str, Any], 
                               previous_scans: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Use AI to generate optimal scan strategy for a target.
        
        Args:
            target: Target hostname or IP
            target_info: Target characteristics
            previous_scans: Optional previous scan results
            
        Returns:
            Scan strategy dictionary with Nmap arguments and reasoning
        """
        if not self.enabled:
            # Fallback strategy
            return {
                "ports": [80, 443, 8080, 8443],
                "technique": "tcp_syn",
                "reasoning": "AI unavailable - using default strategy",
                "nmap_args": ["-sS", "-p", "80,443,8080,8443"]
            }
        
        prompt = f"""As an expert Nmap reconnaissance specialist, generate an optimal port scanning strategy for this target.

Target: {target}
Target Info: {json.dumps(target_info, indent=2)}
Previous Scans: {json.dumps(previous_scans or [], indent=2)}

Generate a comprehensive scan strategy considering:
1. Optimal Nmap technique (SYN, connect, UDP, etc.)
2. Port selection (common ports, service-specific, or full scan)
3. Timing and stealth requirements
4. WAF/IDS evasion if needed
5. Service detection intensity

Return JSON:
{{
  "technique": "tcp_syn",
  "ports": [80, 443, 8080],
  "nmap_args": ["-sS", "-p", "80,443,8080", "-sV", "--version-intensity", "5"],
  "reasoning": "SYN scan recommended for speed and stealth. Focus on web ports based on domain pattern.",
  "confidence": 0.85,
  "alternative_strategies": [
    {{"if": "WAF detected", "strategy": {{"nmap_args": ["-sS", "-D", "RND:5,ME", "-g", "443"]}}}}
  ]
}}

Return ONLY valid JSON, no markdown."""
        
        response = self._call_llm(prompt, max_tokens=800)
        
        if not response:
            # Fallback
            return {
                "ports": [80, 443, 8080, 8443],
                "technique": "tcp_syn",
                "reasoning": "AI unavailable",
                "nmap_args": ["-sS", "-p", "80,443,8080,8443"]
            }
        
        try:
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
                response = response.strip()
            
            strategy = json.loads(response)
            logger.info(f"✅ AI generated scan strategy for {target}")
            return strategy
            
        except Exception as e:
            logger.error(f"Failed to parse strategy response: {e}")
            return {
                "ports": [80, 443, 8080, 8443],
                "technique": "tcp_syn",
                "reasoning": f"AI parsing failed: {e}",
                "nmap_args": ["-sS", "-p", "80,443,8080,8443"]
            }
    
    def analyze_scan_results(self, target: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use AI to analyze scan results and extract insights.
        
        Args:
            target: Target that was scanned
            scan_results: Scan results dictionary
            
        Returns:
            Analysis with security concerns, findings, and recommendations
        """
        if not self.enabled:
            return {
                "summary": "AI analysis unavailable",
                "security_concerns": [],
                "findings": [],
                "risk_level": "unknown"
            }
        
        prompt = f"""As a cybersecurity analyst, analyze these port scan results and provide insights.

Target: {target}
Scan Results: {json.dumps(scan_results, indent=2)}

Analyze:
1. Security concerns (exposed services, misconfigurations)
2. Interesting findings (unusual ports, service versions)
3. Risk level (low, medium, high, critical)
4. Recommendations for next steps

Return JSON:
{{
  "summary": "Brief summary of findings",
  "security_concerns": ["Exposed SSH on port 22", "Outdated Apache version"],
  "interesting_findings": ["Custom service on port 8080", "TLS 1.0 detected"],
  "risk_level": "medium",
  "recommendations": ["Deep scan port 8080", "Check for vulnerabilities in Apache 2.4.41"],
  "next_actions": ["vulnerability_scan", "service_enumeration"]
}}

Return ONLY valid JSON, no markdown."""
        
        response = self._call_llm(prompt, max_tokens=600)
        
        if not response:
            return {
                "summary": "AI analysis unavailable",
                "security_concerns": [],
                "findings": [],
                "risk_level": "unknown"
            }
        
        try:
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
                response = response.strip()
            
            analysis = json.loads(response)
            logger.info(f"✅ AI analyzed scan results for {target}")
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to parse analysis: {e}")
            return {
                "summary": f"Analysis parsing failed: {e}",
                "security_concerns": [],
                "findings": [],
                "risk_level": "unknown"
            }
    
    def decide_next_action(self, target: str, scan_results: Dict[str, Any], 
                          analysis: Optional[Dict] = None) -> AgenticDecision:
        """
        Use AI to decide what action to take next based on scan results.
        
        Args:
            target: Target that was scanned
            scan_results: Scan results
            analysis: Optional previous analysis
            
        Returns:
            AgenticDecision with recommended action and reasoning
        """
        if not self.enabled:
            return AgenticDecision(
                action="scan",
                reasoning="AI unavailable - continue normal scanning",
                confidence=0.5,
                parameters={},
                next_steps=["Continue to next target"]
            )
        
        prompt = f"""As an autonomous reconnaissance agent, decide what action to take next based on these scan results.

Target: {target}
Scan Results: {json.dumps(scan_results, indent=2)}
Analysis: {json.dumps(analysis or {}, indent=2)}

Available actions:
1. "deep_scan" - Perform deeper port scanning (more ports, service enumeration)
2. "vulnerability_scan" - Scan for known vulnerabilities
3. "service_enumeration" - Enumerate services on open ports
4. "move_next" - This target is complete, move to next
5. "pause" - Pause for human review (critical findings)
6. "skip" - Skip similar targets (low value)

Consider:
- Risk level of findings
- Value of additional scanning
- Resource efficiency
- Priority of other targets

Return JSON:
{{
  "action": "deep_scan",
  "reasoning": "Multiple interesting services found, deeper scan recommended",
  "confidence": 0.85,
  "parameters": {{"ports": "all", "service_detection": true}},
  "next_steps": ["Scan all 65535 ports", "Enumerate services", "Check for vulnerabilities"]
}}

Return ONLY valid JSON, no markdown."""
        
        response = self._call_llm(prompt, max_tokens=400)
        
        if not response:
            return AgenticDecision(
                action="move_next",
                reasoning="AI unavailable",
                confidence=0.5,
                parameters={},
                next_steps=["Continue to next target"]
            )
        
        try:
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
                response = response.strip()
            
            decision_data = json.loads(response)
            
            return AgenticDecision(
                action=decision_data.get('action', 'move_next'),
                reasoning=decision_data.get('reasoning', 'No reasoning provided'),
                confidence=float(decision_data.get('confidence', 0.5)),
                parameters=decision_data.get('parameters', {}),
                next_steps=decision_data.get('next_steps', [])
            )
            
        except Exception as e:
            logger.error(f"Failed to parse decision: {e}")
            return AgenticDecision(
                action="move_next",
                reasoning=f"Decision parsing failed: {e}",
                confidence=0.5,
                parameters={},
                next_steps=["Continue to next target"]
            )
    
    def is_available(self) -> bool:
        """Check if agentic AI is available"""
        return self.enabled


# Global instance
_agentic_kage_instance = None

def get_agentic_kage(llm_gateway_url: str = "http://localhost:8082", 
                     api_key: Optional[str] = None) -> AgenticKageExtension:
    """Get or create agentic Kage extension instance"""
    global _agentic_kage_instance
    
    if _agentic_kage_instance is None:
        _agentic_kage_instance = AgenticKageExtension(llm_gateway_url, api_key)
    
    return _agentic_kage_instance

