import os
import logging
import time
import requests
import ipaddress
from user_agents import parse as ua_parse

GEOIP_DB = 'GeoLite2-City.mmdb'
GEO_CACHE = {}
REQUEST_DELAY = 1.5  # seconds between API requests

class GeoIPResolver:
    """Handles IP geolocation with caching and rate limiting"""
    def __init__(self):
        self.geo_reader = None
        self.use_local = False
        self.setup_geo_reader()
        
    def setup_geo_reader(self):
        """Initialize GeoIP database reader"""
        if os.path.exists(GEOIP_DB):
            try:
                self.geo_reader = geoip2.database.Reader(GEOIP_DB)
                self.use_local = True
                logging.info(f"Using local GeoIP DB: {GEOIP_DB}")
            except Exception as e:
                logging.error(f"Error loading GeoIP DB: {str(e)}")
                self.use_local = False
        else:
            logging.warning("GeoIP DB not found; using ip-api.com HTTP API")
    
    def resolve_ip(self, ip):
        """Resolve IP information with caching and rate limiting"""
        if not ip or ip in ['', 'N/A', 'unknown']:
            return {}
            
        if ip in GEO_CACHE:
            return GEO_CACHE[ip]
        
        try:
            # Validate IP format
            ipaddress.ip_address(ip)
        except ValueError:
            logging.warning(f"Invalid IP address: {ip}")
            return {}
        
        result = {}
        
        if self.use_local and self.geo_reader:
            try:
                rec = self.geo_reader.city(ip)
                result = {
                    'country': rec.country.name or '',
                    'city':    rec.city.name or '',
                    'timezone':rec.location.time_zone or '',
                }
            except Exception as e:
                logging.error(f"GeoIP lookup failed for {ip}: {str(e)}")
        else:
            try:
                # Rate limiting
                time.sleep(REQUEST_DELAY)
                resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
                if resp.get('status') == 'success':
                    result = {
                        'country':  resp.get('country', '') or '',
                        'city':     resp.get('city', '') or '',
                        'timezone': resp.get('timezone', '') or '',
                    }
            except Exception as e:
                logging.error(f"API lookup failed for {ip}: {str(e)}")
        
        # Calculate subnet
        try:
            if '.' in ip:  # IPv4
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            else:           # IPv6
                subnet = str(ipaddress.ip_network(f"{ip}/64", strict=False))
            result['subnet'] = subnet
        except Exception as e:
            logging.error(f"Subnet calculation failed for {ip}: {str(e)}")
            result['subnet'] = ''
        
        GEO_CACHE[ip] = result
        return result