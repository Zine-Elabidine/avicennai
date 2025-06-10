import requests
import json



payload = {
	'action_type': 'agent',
	'agent_name': 'socengineer',
	'answer_mode': 'normal',
	'prompt': 'create a detection rule to detect RDP logins from public IP adresses in windows logs',
	'additional_params': {
		'current_rule': '',
		'prompt_type': 'create',
		'rule_type': 'query',
		'chat_history': 'user: hi, assistant: hola !'
	}
}


headers = {
	'Content-Type': 'application/json',
	'accept': 'application/json',
	'X-API-Key': 'your_secret_api_key_here'
}

url = 'http://172.20.227.238:8000/api/v1/engine/process'

response = requests.post(url, data=json.dumps(payload), headers=headers)

if response.status_code == 200:
	print(json.dumps(response.json()))
else:
	print(f"Status: {response.status_code}, Response: {response.text}")