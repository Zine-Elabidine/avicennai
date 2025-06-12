from tavily import TavilyClient
import json
import re
import requests
from virustotal_python import Virustotal
from typing import Dict, Any
from OTXv2 import OTXv2, IndicatorTypes
import logging
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup


# Configure logging
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
   handlers=[
       logging.FileHandler('soc_agent.log'),
       logging.StreamHandler()
   ]
)
logger = logging.getLogger("SOCAgent")

os.environ["LANGSMITH_TRACING"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "soc-agent-research"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGSMITH_API_KEY"] = "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"

TAVILY_API_KEY = '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'
VT_API_KEY = 'eabf1dc36609edf7e05d989da4fd4838c5efe4d18d1d3e239e5a5dac9eeaf9d7'
OTX_API_KEY = 'ddd01f52cd5b3d735d0f6f77adcee847d44160b80f5d9088dd612319fc05078be'







def virustotal_lookup(ioc: str) -> Dict[str, Any]:
    """
    This function support only the following IOCs list: IP address, domain and file hashes
    Queries VirusTotal for an IOC (file hash, IP address, or domain) and returns a detailed result.
    Don't use this tool with URLs

    Description:
        This function auto-detects the IOC type, fetches its reputation data from VirusTotal,
        and returns a structured dictionary containing:
          - Whether the IOC is malicious.
          - The count of engines flagging it as malicious versus benign.
          - A computed severity rating.
          - For file hashes, the best-guess malware type.
          - Only related IOCs that are themselves malicious (as determined by individual lookups).
          - Raw attributes data from the VirusTotal response.
    
    Args:
        api_key (str): Your VirusTotal API key.
        ioc (str): The Indicator of Compromise. This can be:
                   - A file hash (MD5, SHA1, or SHA256),
                   - An IPv4 address, or
                   - A domain name.
    
    Returns:
        dict: A dictionary with the following structure:
            {
                "ioc": <str>,                # The original IOC queried.
                "ioc_type": <str>,           # Detected type: "file", "ip", or "domain".
                "malicious": <bool>,         # True if IOC is flagged as malicious.
                "malicious_count": <int>,    # Number of engines flagging malicious.
                "benign_count": <int>,       # Number of engines flagging benign/undetected.
                "severity": <str>,           # Severity rating ("High", "Medium", "Low", "None").
                "malware_type": <str|null>,  # For file hashes, a suggested malware type.
                "related_iocs": {            # Only malicious related IOCs.
                    "ips": [<str>, ...],
                    "domains": [<str>, ...],
                    "files": [<str>, ...]
                },
                "raw_attributes": <dict>     # Raw response attributes from VirusTotal.
            }
    
    Raises:
        Exception: If there is an error during the API request.
    
    Examples:
        >>> VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
        >>> # Lookup for an IP address
        >>> result = virustotal_lookup("8.8.8.8")
        >>> print(result)
        {
            "ioc": "8.8.8.8",
            "ioc_type": "ip",
            "malicious": True,
            "malicious_count": 3,
            "benign_count": 12,
            "severity": "Medium",
            "malware_type": None,
            "related_iocs": {
                "ips": ["1.2.3.4"],
                "domains": ["malicious-example.com"],
                "files": ["abcdef1234567890abcdef1234567890"]
            },
            "raw_attributes": { ... }
        }
        
        >>> # Lookup for a file hash
        >>> result = virustotal_lookup("44d88612fea8a8f36de82e1278abb02f")
        >>> print(result)
    """
    if not ioc:
       raise ValueError("The IOC must be a non-empty string.")
   
    try:
        logger.info(f"Calling tool virustotal_lookup with query: {ioc}")
        return vt_lookup_ioc(VT_API_KEY, ioc)
    except Exception as e:
        logger.error(f"Error in virustotal_lookup tool: {str(e)}")
        return {
            "ioc": ioc,
            "error": f"Error querying VirusTotal: {str(e)}",
            "severity": "Unknown",
            "malicious": False,
            "malicious_count": 0,
            "benign_count": 0
        }
        
        
        
        
def websearch(query: str) -> str:
   """
   Perform a web search and retrieve the top result.

   Args:
       query (str): A string representing the search query. For example, 'latest advancements in AI'. Use few keywords only not long phrases.

   Returns:
       str: A brief summary of the top search result.

    Raises:
        ValueError: If the query is empty or None.

    Example:
        result = websearch('current weather in Paris')
   """
   if not query:
       raise ValueError("The search query must be a non-empty string.")
   
   try:
       logger.info(f"Calling tool websearch with query: {query}")
       answer = tool_websearch_general_answer(query)
       return answer
   except Exception as e:
       logger.error(f"Error in websearch tool: {str(e)}")
       return f"Error performing web search: {str(e)}. Please try a different query or approach."







def websearch_threat(query: str) -> str:
    """
    Perform a threat-specific web search using Tavily API.

    Args:
        query (str): Search keywords (e.g., 'latest ransomware attack').

    Returns:
        str: A concise summary or raw content from high-risk cybersecurity domains.
    """
    if not query:
        raise ValueError("The search query must be a non-empty string.")
    
    try:
        logger.info(f"Calling tool websearch threat with query: {query}")
        answer = tool_websearch_threat_answer(query)
        return answer
    except Exception as e:
        logger.error(f"Error in websearch threat tool: {str(e)}")
        return f"Error performing threat web search: {str(e)}. Please try a different query or approach."





threat_websites = [
    "adsecurity.org",
    "elastic.co",
    "cybertriage.com",
    "hackthebox.com",
    "attack.mitre.org",
    "secura.com",
    "xpnsec.com",
    "redcanary.com",
    "detect.fyi",
    "splunk.com",
    "withsecure.com",
    "specterops.io",
    "jpcert.or.jp",
    "microsoft.com",
    "palantir.com",
    "sans.org",
	"docs.aws.amazon.com",
	"cloud.google.com",
	"nccgroup.com",
	"netwrix.com",
	"thedfirreport.com",
	"nviso.eu",
	"cyber.gov.au"

]



def tool_websearch_threat(query: str) -> str:
    """
    Perform a threat-specific web search using Tavily API.

    Args:
        query (str): Search keywords (e.g., 'latest ransomware attack').

    Returns:
        str: A concise summary or raw content from high-risk cybersecurity domains.
    """
    tavily_client = TavilyClient(api_key=TAVILY_API_KEY)
    
    response = tavily_client.search(
        query=query,
        search_depth="advanced",
        include_domains=threat_websites,
        include_answer="advanced",
        include_raw_content=True,
        max_results=5
    )

    return response

def tool_websearch_general(query):
	
	tavily_client = TavilyClient(api_key=TAVILY_API_KEY)
	response = tavily_client.search(query=query,
		search_depth="advanced",
		include_answer="advanced",
		include_raw_content=True,
		max_results=5)

	return response

def tool_websearch_threat_answer(query):
	return tool_websearch_threat(query)['answer']

def tool_websearch_general_answer(query):
	return tool_websearch_general(query)['answer']

def tool_websearch_threat_content(query):

	content = ""
	response = tool_websearch_threat(query)
	content += response['answer'] + "\n"
	for resp in response['results']:
		content += resp['content']
	return content

def tool_websearch_general_content(query):

	content = ""
	response = tool_websearch_general(query)
	content += response['answer'] + "\n"
	for resp in response['results']:
		content += resp['content']
	return content






def _detect_ioc_type(ioc: str) -> str:
    """
    A naive helper to detect whether an IOC is a hash, IP address, or domain.
    - If it contains only hex chars and length in {32,40,64} => treat as file hash (MD5, SHA1, SHA256).
    - If it matches an IP (v4) regex => 'ip'.
    - Otherwise => 'domain'.
    """
    # Check for hash (MD5=32 hex, SHA1=40 hex, SHA256=64 hex).
    # You can adjust or expand for other hash lengths if needed.
    lower_ioc = ioc.lower()
    if re.fullmatch(r"[0-9a-f]{32}", lower_ioc):
        return "file"  # MD5
    elif re.fullmatch(r"[0-9a-f]{40}", lower_ioc):
        return "file"  # SHA1
    elif re.fullmatch(r"[0-9a-f]{64}", lower_ioc):
        return "file"  # SHA256
    
    # Check for IPv4
    ip_pattern = r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$"
    if re.fullmatch(ip_pattern, ioc):
        return "ip"
    
    # Otherwise assume domain
    return "domain"

def _compute_severity(malicious_count: int, total_count: int) -> str:
    """
    Returns a simple severity rating based on malicious engine counts.
    Customize thresholds as you see fit.
    """
    if malicious_count == 0:
        return "None"
    ratio = malicious_count / (total_count or 1)
    # Example thresholds:
    if ratio >= 0.6 or malicious_count >= 10:
        return "High"
    elif ratio >= 0.3 or malicious_count >= 5:
        return "Medium"
    else:
        return "Low"

def _is_ioc_malicious(vtotal: Virustotal, ioc: str, ioc_type: str) -> bool:
    """
    Helper that performs a quick check to see if the given IOC is malicious (malicious_count > 0).
    """
    if ioc_type == "file":
        endpoint = f"files/{ioc}"
    elif ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
    else:  # domain
        endpoint = f"domains/{ioc}"
    
    try:
        resp = vtotal.request(endpoint)
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return malicious_count > 0
    except Exception:
        return False

def vt_lookup_ioc(api_key: str, ioc: str, verbose: bool = False) -> Dict[str, Any]:
    """
    A function that takes an IOC (IP, domain, or hash) and:
    1. Auto-detects IOC type (file hash, IP, or domain).
    2. Queries VirusTotal using virustotal-python.
    3. Returns:
       - malicious or not
       - how many engines flagged it malicious vs. benign
       - severity rating
       - best-guess malware type (for files)
       - related IOCs
    """
    vtotal = Virustotal(API_KEY=api_key)
    ioc_type = _detect_ioc_type(ioc)

    # Prepare a default result structure
    result = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "malicious": False,
        "malicious_count": 0,
        "benign_count": 0,
        "severity": "None",
        "malware_type": None,
        #"related_iocs": {},  # We'll store lists of related IPs, domains, hashes, etc.
        #"raw_attributes": {}
    }

    if verbose:
        result["raw_attributes"] = {}
        result["related_iocs"] = {}

    # Determine the relevant endpoint and relationships to fetch
    # For files: 'files/{hash}' + relationships = contacted_ips, contacted_domains, similar_files
    # For domains: 'domains/{domain}' + relationships = communicating_files, downloaded_files, referrer_files, resolutions
    # For ip: 'ip_addresses/{ip}' + relationships = communicating_files, downloaded_files, resolutions
    if ioc_type == "file":
        endpoint = f"files/{ioc}"
        relationships = "contacted_ips,contacted_domains,similar_files"
    elif ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
        relationships = "communicating_files,downloaded_files,resolutions"
    else:  # domain
        endpoint = f"domains/{ioc}"
        relationships = "communicating_files,downloaded_files,referrer_files,resolutions"
    
    try:
        resp = vtotal.request(
            endpoint,
            params={"relationships": relationships}
        )
        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        if verbose:
            result["raw_attributes"] = attributes  # If you want to expose raw info
        
        # 1) Compute malicious / benign from last_analysis_stats
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        benign_count = stats.get("harmless", 0) + stats.get("undetected", 0)
        total_count = sum(stats.values())
        
        # Fill in malicious, counts, severity
        result["malicious_count"] = malicious_count
        result["benign_count"] = benign_count
        result["malicious"] = (malicious_count > 0)
        result["severity"] = _compute_severity(malicious_count, total_count)
        
        # 2) If file, try to identify malware type
        if ioc_type == "file":
            # popular_threat_classification can provide threat labels
            ptc = attributes.get("popular_threat_classification", {})
            suggested_threat_label = ptc.get("suggested_threat_label")
            if suggested_threat_label:
                result["malware_type"] = suggested_threat_label
            else:
                # fallback: try type_description
                result["malware_type"] = attributes.get("type_description")
        
        # 3) Gather related IOCs from relationships
        relationships_data = data.get("relationships", {})
        related_iocs = {
            "ips": [],
            "domains": [],
            "files": []
        }

        found_related_ips = []
        found_related_domains = []
        found_related_files = []

        for rel_name, rel_info in relationships_data.items():
            related_data = rel_info.get("data", [])
            for obj in related_data:
                obj_id = obj.get("id", "")
                obj_type = obj.get("type", "")
                if obj_type == "ip_address":
                    found_related_ips.append(obj_id)
                elif obj_type == "domain":
                    found_related_domains.append(obj_id)
                elif obj_type == "file":
                    found_related_files.append(obj_id)



        # For each requested relationship, parse out the data array
        for rel_name, rel_info in relationships_data.items():
            if "data" not in rel_info:
                continue
            for obj in rel_info["data"]:
                obj_id = obj.get("id", "")
                obj_type = obj.get("type", "")
                
                # "ip_address", "domain", or "file"
                if obj_type == "ip_address":
                    related_iocs["ips"].append(obj_id)
                elif obj_type == "domain":
                    related_iocs["domains"].append(obj_id)
                elif obj_type == "file":
                    related_iocs["files"].append(obj_id)

        # 4) Check each related IOC's own malicious status
        malicious_ips = []
        malicious_domains = []
        malicious_files = []

        # For performance, you might limit how many related IOCs to check
        for ip in found_related_ips:
            if _is_ioc_malicious(vtotal, ip, "ip"):
                malicious_ips.append(ip)

        for dom in found_related_domains:
            if _is_ioc_malicious(vtotal, dom, "domain"):
                malicious_domains.append(dom)

        for f in found_related_files:
            if _is_ioc_malicious(vtotal, f, "file"):
                malicious_files.append(f)

        related_iocs = {
            "ips": malicious_ips,
            "domains": malicious_domains,
            "files": malicious_files
        }
        

        if result["malicious"] or verbose:
            result["related_iocs"] = related_iocs

    except Exception as e:
        result["error"] = str(e)
    
    return result


def vt_lookup_hash(api_key: str, file_hash: str) -> dict:
    """
    Queries VirusTotal for a file hash using virustotal-python.
    Returns JSON-like dict, including whether it's malicious and any related IOCs.
    """
    vtotal = Virustotal(API_KEY=api_key)
    result = {
        "type": "hash",
        "query": file_hash,
        "attributes": {},
        "malicious": False,
        "related_iocs": {}
    }
    try:
        # Request file details + relationships (contacted_ips, contacted_domains, similar_files)
        # We add "params" to fetch those relationships in the same response
        resp = vtotal.request(
            f"files/{file_hash}",
            params={"relationships": "contacted_ips,contacted_domains,similar_files"}
        )
        json_resp = resp.json()

        data = json_resp.get("data", {})
        attributes = data.get("attributes", {})
        result["attributes"] = attributes

        # Check if malicious
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        if malicious_count > 0:
            result["malicious"] = True

            # Get relationship data
            relationships = data.get("relationships", {})
            related_iocs = {}

            contacted_ips = relationships.get("contacted_ips", {}).get("data", [])
            if contacted_ips:
                related_iocs["contacted_ips"] = [ip.get("id") for ip in contacted_ips]

            contacted_domains = relationships.get("contacted_domains", {}).get("data", [])
            if contacted_domains:
                related_iocs["contacted_domains"] = [dom.get("id") for dom in contacted_domains]

            similar_files = relationships.get("similar_files", {}).get("data", [])
            if similar_files:
                related_iocs["similar_files"] = [f.get("id") for f in similar_files]

            result["related_iocs"] = related_iocs
    except Exception as e:
        result["error"] = str(e)

    return result


def vt_lookup_ip(api_key: str, ip_address: str) -> dict:
    """
    Queries VirusTotal for an IP address using virustotal-python.
    Returns a JSON-like dict with reputation details.
    """
    vtotal = Virustotal(API_KEY=api_key)
    result = {
        "type": "ip",
        "query": ip_address,
        "attributes": {},
    }
    try:
        resp = vtotal.request(f"ip_addresses/{ip_address}")
        json_resp = resp.json()
        result["attributes"] = json_resp.get("data", {}).get("attributes", {})
    except Exception as e:
        result["error"] = str(e)

    return result


def vt_lookup_domain(api_key: str, domain: str) -> dict:
    """
    Queries VirusTotal for a domain using virustotal-python.
    Returns a JSON-like dict with reputation details.
    """
    vtotal = Virustotal(API_KEY=api_key)
    result = {
        "type": "domain",
        "query": domain,
        "attributes": {},
    }
    try:
        resp = vtotal.request(f"domains/{domain}")
        json_resp = resp.json()
        result["attributes"] = json_resp.get("data", {}).get("attributes", {})
    except Exception as e:
        result["error"] = str(e)

    return result


def otx_lookup_hash(api_key: str, file_hash: str) -> dict:
    """
    Queries AlienVault OTX for a file hash using OTXv2.
    Returns JSON-like dict, including related IOCs if malicious.
    """
    otx = OTXv2(api_key)
    results = {
        "type": "hash",
        "query": file_hash,
        "otx_results": None,
        "malicious": False,
        "related_iocs": {}
    }

    try:
        # Choose correct IndicatorTypes if needed: FILE_HASH_MD5, FILE_HASH_SHA1, or FILE_HASH_SHA256
        # Using SHA256 as an example
        resp = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, file_hash)
        results["otx_results"] = resp

        # Check pulses for malicious verdict
        pulses = resp.get("pulse_info", {}).get("pulses", [])
        if pulses:
            results["malicious"] = True

            # Gather related IOCs
            related_ips = set()
            related_domains = set()
            related_hashes = set()

            for pulse in pulses:
                indicators = pulse.get("indicators", [])
                for ioc in indicators:
                    ioc_type = ioc.get("type")
                    ioc_value = ioc.get("indicator")
                    if ioc_type == "IPv4":
                        related_ips.add(ioc_value)
                    elif ioc_type in ["domain", "hostname"]:
                        related_domains.add(ioc_value)
                    elif ioc_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]:
                        # Avoid re-listing the same file hash
                        if ioc_value.lower() != file_hash.lower():
                            related_hashes.add(ioc_value)

            results["related_iocs"] = {
                "ips": list(related_ips),
                "domains": list(related_domains),
                "other_file_hashes": list(related_hashes)
            }

    except Exception as e:
        results["error"] = str(e)
    return results


def otx_lookup_ip(api_key: str, ip_address: str) -> dict:
    """
    Queries AlienVault OTX for an IP address using OTXv2.
    Returns a JSON-like dict with any details or pulses.
    """
    otx = OTXv2(api_key)
    results = {
        "type": "ip",
        "query": ip_address,
        "otx_results": None
    }

    try:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
        results["otx_results"] = indicator_details
    except Exception as e:
        results["error"] = str(e)
    return results


def otx_lookup_domain(api_key: str, domain: str) -> dict:
    """
    Queries AlienVault OTX for a domain using OTXv2.
    Returns a JSON-like dict with any details or pulses.
    """
    otx = OTXv2(api_key)
    results = {
        "type": "domain",
        "query": domain,
        "otx_results": None
    }

    try:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        results["otx_results"] = indicator_details
    except Exception as e:
        results["error"] = str(e)
    return results

def url_content_analysis(url: str, search_keywords: str = "") -> Dict[str, Any]:
    """
    Visit a specific URL and analyze its content for useful information.
    
    Args:
        url (str): The URL to visit and analyze
        search_keywords (str, optional): Specific keywords to search for in the content
        
    Returns:
        Dict[str, Any]: A dictionary containing:
            - url: The original URL
            - status_code: HTTP response status code
            - title: Page title if available
            - content_summary: Brief summary of the page content
            - keywords_found: Boolean indicating if search keywords were found
            - security_indicators: Any potential security-related information found
            - extracted_text: First 1000 characters of cleaned text content
            - error: Error message if any issues occurred
    """
    if not url:
        raise ValueError("URL must be a non-empty string.")
    
    # Ensure URL has a proper scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "url": url,
        "status_code": None,
        "title": None,
        "content_summary": None,
        "keywords_found": False,
        "security_indicators": [],
        "extracted_text": None,
        "error": None
    }
    
    try:
        logger.info(f"Calling tool url_content_analysis with URL: {url}")
        
        # Set headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Make the request with timeout
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        result["status_code"] = response.status_code
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                result["title"] = title_tag.get_text().strip()
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text content
            text_content = soup.get_text()
            
            # Clean up text (remove extra whitespace)
            lines = (line.strip() for line in text_content.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            clean_text = ' '.join(chunk for chunk in chunks if chunk)
            
            # Store first 1000 characters for analysis
            result["extracted_text"] = clean_text[:1000] if clean_text else ""
            
            # Create content summary
            if clean_text:
                # Take first few sentences for summary
                sentences = clean_text.split('. ')
                summary_sentences = sentences[:3] if len(sentences) >= 3 else sentences
                result["content_summary"] = '. '.join(summary_sentences)
                if result["content_summary"] and not result["content_summary"].endswith('.'):
                    result["content_summary"] += '.'
            
            # Search for keywords if provided
            if search_keywords:
                keywords_list = [kw.strip().lower() for kw in search_keywords.split(',')]
                text_lower = clean_text.lower()
                found_keywords = [kw for kw in keywords_list if kw in text_lower]
                result["keywords_found"] = len(found_keywords) > 0
                if found_keywords:
                    result["found_keywords_list"] = found_keywords
            
            # Look for security-related indicators
            security_indicators = []
            security_keywords = [
                'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'suspicious',
                'threat', 'attack', 'exploit', 'vulnerability', 'breach', 'compromise',
                'infected', 'backdoor', 'rootkit', 'botnet', 'scam', 'fraud'
            ]
            
            text_lower = clean_text.lower()
            for indicator in security_keywords:
                if indicator in text_lower:
                    security_indicators.append(indicator)
            
            result["security_indicators"] = list(set(security_indicators))  # Remove duplicates
            
        else:
            result["error"] = f"HTTP {response.status_code}: Unable to fetch content"
            
    except requests.exceptions.Timeout:
        result["error"] = "Request timeout - the server took too long to respond"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection error - unable to reach the URL"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error analyzing URL: {str(e)}"
        logger.error(f"Error in url_content_analysis tool: {str(e)}")
    
    return result