import os
required_tools=["7z","patchelf","eu-unstrip","wget","patchelf"]
def check_requirement():
	for tool in required_tools:
		if os.system(f"which {tool} 1>/dev/null"):
			raise Exception(f"Plz install {tool}")