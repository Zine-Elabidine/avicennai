"""
Wrapper functions for TheHive4py v2.0.0b9 to manage SOC cases via TheHive API.
Each function uses a shared `_get_api()` helper that instantiates TheHiveApi client with URL, API key, and optional organisation.
Functions include: create_case, update_case, close_case, get_case, get_case_description,
update_case_description, merge_cases, search_cases. A `main()` demonstrates usage.
"""


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from thehive4py import TheHiveApi  # client entrypoint
from thehive4py.query.filters import Eq  # filter builder for queries
from thehive4py.query.filters import FilterExpr
from typing import List, Optional, Sequence, Union, Dict
import logging

import requests

# Import settings from config
from app.core.config import settings

# Set up logger
logger = logging.getLogger("TheHive4API")




def _get_api(org: str = None, verify: bool = None) -> TheHiveApi:
    """
    Instantiate and return a TheHiveApi client with credentials from config and optional organisation.

    :param org: optional organisation name for X-Organisation header
    :param verify: whether to verify TLS certificate (defaults to config setting)
    :return: TheHiveApi instance
    """
    return TheHiveApi(url=settings.THEHIVE_API_URL, apikey=settings.THEHIVE_API_KEY, organisation=org, verify=verify)  # organisation header set by client


def create_case(case_data: dict, org: str = None) -> dict:
    """
    Create a new case in TheHive.

    :param case_data: fields for the case (e.g. title, description, severity)
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of created case, including '_id'
    """
    api = _get_api(org)
    return api.case.create(case=case_data)  # uses case.create endpoint


def update_case(case_id: str, case, org: str = None) -> Union[Dict, str, None]:
    """
    Update attributes of an existing case.

    :param case_id: ID of the case to update
    :param case: dict of fields to update (e.g. {'status': 'InProgress'})
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of updated case, string, or None depending on API version
    """
    api = _get_api(org)
    try:
        # Try TheHive5 API format first
        result = api.case.update(case_id=case_id, case=case)
        return result
    except TypeError:
        # Fall back to TheHive4 API format
        result = api.case.update(case_id=case_id, fields=case)
        return result
    except Exception as e:
        logger.error(f"Error updating case {case_id}: {str(e)}")
        raise


def close_case(case_id: str, org: str = None) -> dict:
    """
    Close a case by setting its status to 'Resolved'.
    Other possible values: Duplicated,Resolved,Open

    :param case_id: ID of the case to close
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of closed case
    """
    # No direct close method; update status field instead
    update_case(case_id, {"status": "Resolved"})


def get_case(case_id: str, org: str = None) -> dict:
    """
    Retrieve full details of a case. 

    :param case_id: ID of the case to fetch
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of case details
    """
    api = _get_api(org)
    return api.case.get(case_id=case_id)  # uses case.get endpoint


def get_case_description(case_id: str, org: str = None) -> str:
    """
    Fetch only the description field of a case.

    :param case_id: ID of the case
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: description string
    """
    case = get_case(case_id, org)
    return case.get("description", "")


def update_case_description(case_id: str, description: str, org: str = None) -> dict:
    """
    Update the description of a case.

    :param case_id: ID of the case
    :param description: new description text
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of updated case
    """
    return update_case(case_id, {"description": description}, org)


def merge_cases(source_case_id: str, target_case_id: str, org: str = None) -> dict:
    """
    Merge one case into another.

    :param source_case_id: ID of case to merge from
    :param target_case_id: ID of case to merge into
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: JSON dict of merge job status
    """
    api = _get_api(org)
    return api.case.merge(case_ids=[source_case_id, target_case_id]) 


def search_cases(
    filters: Optional[FilterExpr] = None,
    sortby: dict = None,
    paginate: dict = None,
    org: str = None
) -> list:
    """
    Search for cases using arbitrary criteria.

    :param filters: dict of filter expressions (e.g. {"title": "Test"}) or full-text via {"_text_": "keyword"}
    :param sortby: optional sort specification, e.g. {"createdAt": "desc"}
    :param paginate: optional pagination spec, e.g. {"page": 1, "perPage": 10}
    :param org: optional organisation name
    :param verify: whether to verify TLS certificate
    :return: list of matching case JSON dicts
    """
    api = _get_api(org)
    # Convert dict filters into list of Query objects

    return api.case.find(filters=filters)


# --- Observable functions ---
def add_observable(case_id: str, observable: dict, org: str = None) -> List:
    """
    Add an observable to a case.

    :param case_id: ID of the case
    :param observable: dict with observable properties (e.g. {'data': '1.2.3.4', 'dataType': 'ip'})
    :param org: optional organisation
    :param verify: TLS verification
    :return: List of created observable objects
    """
    api = _get_api(org)
    return api.case.create_observable(case_id=case_id, observable=observable)


def get_observables(case_id: str, org: str = None) -> list:
    """
    Retrieve observables of a case.

    :param case_id: ID of the case
    :param org: optional organisation
    :param verify: TLS verification
    :return: list of observable JSON dicts
    """
    api = _get_api(org)
    return api.case.find_observables(case_id=case_id)


# --- Task functions ---

def create_case_task(case_id: str, title: str, description: str = "", status: str = "Waiting", owner: Optional[str] = None) -> Dict:
    """Create a task in a case"""
    # Ensure proper URL path construction
    base_url = settings.THEHIVE_API_URL
    url = f"{base_url}/api/case/{case_id}/task"
    
    headers = {
        'Authorization': f'Bearer {settings.THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }
        
    payload = {
        "title": title,
        "description": description,
        "status": status
    }
        
    if owner:
        payload["owner"] = owner
        
    response = requests.post(url, headers=headers, json=payload, verify=settings.THEHIVE_VERIFY_SSL)
    response.raise_for_status()
    return response.json()

# --- Case flagging ---
def flag_case(case_id: str, flag: bool = True, org: str = None) -> Union[Dict, str, None]:
    """
    Add a flag to a case (e.g. "false-positive", "true-positive").

    :param case_id: ID of the case
    :param flag: flag string
    :param org: optional organisation
    :param verify: TLS verification
    :return: JSON dict of updated case
    """
    return update_case(case_id, {"flag": flag}, org)


# --- LLM-friendly wrapper functions ---
#================================================================================================================

def thehive_get_case(case_id: str) -> dict:
    """
    Get details of a case from TheHive.
    
    :param case_id: ID of the case to retrieve
    :return: Dictionary with case details
    """
    logger.info(f"Calling thehive_get_case with case_id: {case_id}")
    try:
        case = get_case(case_id)
        return {
            "success": True,
            "id": case.get("_id", ""),
            "title": case.get("title", ""),
            "description": case.get("description", ""),
            "severity": case.get("severity", 0),
            "status": case.get("status", ""),
            "tags": case.get("tags", []),
            "flag": case.get("flag", False)
        }
    except Exception as e:
        logger.error(f"Error in thehive_get_case: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to retrieve case {case_id}: {str(e)}"
        }
    
def thehive_create_case(title: str, description: str, severity: int = 2, tags: List[str] = None) -> dict:
    """
    Create a new case in TheHive.
    
    :param title: Title of the case
    :param description: Description of the case
    :param severity: Severity level (1-4, where 1 is highest)
    :param tags: List of tags to apply to the case
    :return: Dictionary with created case details
    
    Example:
        thehive_create_case("Malware Detection", "Ransomware detected on host1", 2, ["malware", "ransomware"])
    """
    logger.info(f"Creating case: '{title}' (severity: {severity})")
    try:
        case_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or []
        }
        
        result = create_case(case_data)
        case_id = result.get("_id", "")
        logger.info(f"Case created: ID {case_id}")
        
        return {
            "success": True,
            "id": case_id,
            "title": result.get("title", ""),
            "message": f"Case created successfully with ID: {case_id}"
        }
    except Exception as e:
        logger.error(f"Error creating case: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to create case: {str(e)}"
        }
    
def thehive_update_case(case_id: str, update_data: dict) -> dict:
    """
    Update a case in TheHive.
    
    :param case_id: ID of the case to update
    :param update_data: Dictionary of fields to update (e.g., {'status': 'InProgress'}, {'description': 'New description'})
    :return: Dictionary with result information
    
    Example:
        thehive_update_case("~12345", {"status": "InProgress"})
        thehive_update_case("~12345", {"description": "Updated description"})
        thehive_update_case("~12345", {"severity": 3})
    """
    logger.info(f"Updating case {case_id}")
    try:
        result = update_case(case_id, update_data)
        logger.info(f"Case {case_id} updated successfully")
        
        # Handle different return types
        if isinstance(result, dict):
            return {
                "success": True,
                "id": result.get("_id", ""),
                "message": f"Case {case_id} updated successfully"
            }
        else:
            # Handle string, None, or other return types
            return {
                "success": True,
                "message": f"Case {case_id} updated successfully"
            }
    except Exception as e:
        logger.error(f"Error updating case {case_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to update case {case_id}: {str(e)}"
        }
    
def thehive_add_observable(case_id: str, data: str, data_type: str, tags: List[str] = None) -> dict:
    """
    Add an observable to a case in TheHive.
    
    :param case_id: ID of the case
    :param data: Observable data (e.g. IP address, file hash)
    :param data_type: Type of observable (e.g. 'ip', 'hash', 'url', 'hostname', 'domain', 'email')
    :param tags: List of tags to apply to the observable
    :return: Dictionary with result information
    
    Example:
        thehive_add_observable("~12345", "8.8.8.8", "ip", ["suspicious"])
        thehive_add_observable("~12345", "malware.exe", "filename", ["malware"])
        thehive_add_observable("~12345", "d41d8cd98f00b204e9800998ecf8427e", "hash", ["md5", "malware"])
    """
    logger.info(f"Adding {data_type} observable to case {case_id}")
    try:
        observable = {
            "data": data,
            "dataType": data_type,
            "tags": tags or []
        }
        
        result = add_observable(case_id, observable)
        
        # Handle the list return type from TheHive4py
        if isinstance(result, list):
            if result and isinstance(result[0], dict):
                obs_id = result[0].get("_id", "")
                logger.info(f"Observable added to case {case_id}: ID {obs_id}")
                return {
                    "success": True,
                    "id": obs_id,
                    "message": f"Observable added to case {case_id}"
                }
            else:
                logger.info(f"Observable added to case {case_id}")
                return {
                    "success": True,
                    "message": f"Observable added to case {case_id}"
                }
        elif isinstance(result, dict):
            # Handle if somehow a dict is returned
            obs_id = result.get("_id", "")
            logger.info(f"Observable added to case {case_id}: ID {obs_id}")
            return {
                "success": True,
                "id": obs_id,
                "message": f"Observable added to case {case_id}"
            }
        else:
            # Handle any other return type
            logger.info(f"Observable added to case {case_id}")
            return {
                "success": True,
                "message": f"Observable added to case {case_id}"
            }
    except Exception as e:
        logger.error(f"Error adding observable to case {case_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to add observable to case {case_id}: {str(e)}"
        }
    
def thehive_create_task(case_id: str, title: str, description: str = "") -> dict:
    """
    Create a task in a case in TheHive.
    
    :param case_id: ID of the case
    :param title: Title of the task
    :param description: Description of the task
    :return: Dictionary with result information
    """
    logger.info(f"Creating task '{title}' for case {case_id}")
    try:
        result = create_case_task(case_id, title, description)
        logger.info(f"Task created in case {case_id}")
        return {
            "success": True,
            "id": result.get("_id", ""),
            "title": result.get("title", ""),
            "message": f"Task '{title}' created in case {case_id}"
        }
    except Exception as e:
        logger.error(f"Error creating task in case {case_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to create task in case {case_id}: {str(e)}"
        }
    
def thehive_flag_case(case_id: str, flag: bool = True) -> dict:
    """
    Flag a case in TheHive as true positive or false positive.
    
    :param case_id: ID of the case to flag
    :param flag: True for true positive, False for false positive
    :return: Dictionary with result information
    
    Example:
        thehive_flag_case("~12345", True)  # Mark as true positive
        thehive_flag_case("~12345", False)  # Mark as false positive
    """
    
    logger.info(f"Flagging case {case_id}")
    try:
        result = flag_case(case_id, flag)
        logger.info(f"Case {case_id} flagged successfully")
        
        # Handle different return types
        if isinstance(result, dict):
            return {
                "success": True,
                "id": result.get("_id", ""),
                "message": f"Case {case_id} flagged "
            }
        elif result is None:
            # Sometimes the update might return None if successful
            return {
                "success": True,
                "message": f"Case {case_id} flagged "
            }
        else:
            # Handle any other return type (string, etc.)
            return {
                "success": True,
                "message": f"Case {case_id} flagged"
            }
    except Exception as e:
        logger.error(f"Error flagging case {case_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to flag case {case_id}: {str(e)}"
        }


