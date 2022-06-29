import requests
import os
from dotenv import load_dotenv
from flask import jsonify

load_dotenv()
API_KEY = os.getenv('API_KEY')

link_config = {
    'Content-Type': 'application/json'
}
def location(address):
    response = requests.get(f"http://api.positionstack.com/v1/forward?access_key={API_KEY}&query={address}&output=json",
                            headers=link_config)
    data=response.json()
    lat_coord = data['data'][0]['latitude']
    lng_coord = data['data'][0]['longitude']

    return {"lat": lat_coord, "lng": lng_coord}
