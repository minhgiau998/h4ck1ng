from pydantic import BaseModel, Field
from typing import Optional, List


class GeoIpSchema(BaseModel):
    query: str

    class Config:
        schema_extra = {"example": {"query": "1.1.1.1"}}


class PortForwardSchema(BaseModel):
    ip_address: str
    port: int

    class Config:
        schema_extra = {"example": {"ip_address": "1.1.1.1", "port": 80}}


class TrackPhoneNumberLocationSchema(BaseModel):
    phone_number: str
    country_code: str

    class Config:
        schema_extra = {
            "example": {
                "phone_number": "+842873005588",
                "country_code": "en",
            }
        }


class WebVulnerabilityScannerSchema(BaseModel):
    url: str

    class Config:
        schema_extra = {"example": {"url": "https://www.example.com/products.php?id=1"}}


class EmailFinderSchema(BaseModel):
    email: str

    class Config:
        schema_extra = {"example": {"email": "dunt3@fpt.com.vn"}}


class PasswordGeneratorSchema(BaseModel):
    password_length: int
    alphabets_count: int
    digits_count: int
    special_characters_count: int

    class Config:
        schema_extra = {
            "example": {
                "password_length": 20,
                "alphabets_count": 10,
                "digits_count": 5,
                "special_characters_count": 5,
            }
        }
