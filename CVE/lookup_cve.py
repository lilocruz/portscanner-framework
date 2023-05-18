import requests

class CVELookup:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cve/"

    def lookup_cve(self, cve_id):
        url = f"{self.base_url}/{cve_id}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                cve_data = response.json()
                cve_description = self._extract_cve_description(cve_data)
                return cve_description
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while looking up CVE {cve_id}: {e}")
        return None

    def _extract_cve_description(self, cve_data):
        # Extract relevant information from the CVE data and return it
        cve_info = cve_data['result']['CVE_Items'][0]['cve']
        cve_description = cve_info['description']['description_data'][0]['value']
        return cve_description
