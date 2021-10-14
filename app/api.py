from fastapi import FastAPI, HTTPException
from fastapi import responses
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from typing import Optional
from app.model import GeoIpRequestModel, GeoIpResponseModel, IpAddressResponseModel

import ipaddress
import requests

app = FastAPI()


@app.get("/", tags=["Home"])
def get_root() -> dict:
    return {"message": "Welcome to the h4ck1ng server."}


@app.get(
    "/network/ip-address",
    tags=["Network"],
    response_model=IpAddressResponseModel,
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "ip_address": "1.1.1.1",
                    }
                }
            },
        },
    },
)
def get_ip_address() -> dict:
    response = requests.get("https://api.ipify.org").content.decode("utf8")
    ip = {"ip_address": response}
    data = jsonable_encoder(ip)
    return JSONResponse(content=data)


@app.post(
    "/information-gathering/geo-ip",
    tags=["Information Gathering"],
    response_model=GeoIpResponseModel,
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "query": "1.1.1.1",
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
            },
        },
        422: {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "example": {
                        "query": "1.1.1.1",
                    }
                }
            },
        },
    },
)
def get_geo_ip(geo_ip_request_model: GeoIpRequestModel) -> dict:
    try:
        ip = ipaddress.ip_address(geo_ip_request_model.query)
        response = requests.get("http://ip-api.com/json/{}".format(ip))
        data = jsonable_encoder(response.json())
        return JSONResponse(content=data)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="IP address {} is not valid".format(geo_ip_request_model.query),
        )
