from fastapi import FastAPI, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from typing import Optional
from app.model import GeoIpRequestModel, GeoIpResponseModel

import ipaddress
import requests

app = FastAPI()


@app.get("/", tags=["Home"])
def get_root() -> dict:
    return {"message": "Welcome to the h4ck1ng server."}


@app.post(
    "/information-gathering/geo-ip",
    tags=["Information Gathering"],
    response_model=GeoIpResponseModel,
)
def get_geo_ip(geo_ip_request_model: GeoIpRequestModel) -> dict:
    try:
        print(geo_ip_request_model.query)
        ip = ipaddress.ip_address(geo_ip_request_model.query)
        response = requests.get("http://ip-api.com/json/{}".format(ip))
        print(response.json())
        data = jsonable_encoder(response.json())
        return JSONResponse(content=data)
    except ValueError:
        return {
            "status": False,
            "message": "IP address {} is not valid".format(geo_ip_request_model.query),
        }
