from pydantic import BaseModel, Field
from typing import Optional, List


class GeoIpRequestModel(BaseModel):
    query: str

    class Config:
        schema_extra = {"example": {"query": "1.1.1.1"}}


class GeoIpResponseModel(BaseModel):
    query: str
    status: bool
    country: str
    countryCode: str
    region: str
    regionName: str
    city: str
    zip: str
    lat: float
    lon: float
    timezone: str
    isp: str
    org: str

    class Config:
        schema_extra = {
            "example": {
                "query": "24.48.0.1",
                "status": "success",
                "country": "Canada",
                "countryCode": "CA",
                "region": "QC",
                "regionName": "Quebec",
                "city": "Montreal",
                "zip": "H1K",
                "lat": 45.6085,
                "lon": -73.5493,
                "timezone": "America/Toronto",
                "isp": "Le Groupe Videotron Ltee",
                "org": "Videotron Ltee",
            }
        }
