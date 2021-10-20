from fastapi import FastAPI, HTTPException
from fastapi import responses
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from typing import Optional

from phonenumbers.phonenumberutil import NumberParseException

from app.model import (
    EmailFinderRequestModel,
    GeoIpRequestModel,
    GeoIpResponseModel,
    IpAddressResponseModel,
    PortForwardRequestModel,
    PortForwardResponseModel,
    TrackPhoneNumberLocationRequestModel,
    TrackPhoneNumberLocationResponseModel,
    WebVulnerabilityScannerRequestModel,
)

import ipaddress
import requests
import socket
import phonenumbers
from phonenumbers import geocoder
import validators
import time


tags_metadata = [
    {
        "name": "Hacking",
        "description": "You can enjoy your hacking in here.",
    },
    {
        "name": "Security",
        "description": "You can use these tools to scan your website for security.",
    },
    {
        "name": "Network",
        "description": "You can use these tools to scan your network.",
    },
    {
        "name": "Other",
        "description": "You can do other things in here like getting your password.",
    },
]


description = """
Welcome to H4ck1ng server 💻

You can access this server for free to do some pentest for your website or just have a fun hacking.

_**Disclaim**: I do not take any responsibility for illegal hacking activities. I created this API for security learning and research purposes only._

## Home

You can use this function to test this server if it works or not.

## Hacking

You will be able to:

* **Track phone number location**.
* **Find email**.

## Security

You will be able to:

* **Scan Web Vulnerability**.
* **Scan SSL/TLS** (_not implemented_).
* **Scan Wappalyzer** (_not implemented_).
* **Scan NMAP** (_not implemented_).

## Network

You will be able to:

* **Get your IP address**.
* **Get your location**.
* **Scan port forware**.

## Other

You will be able to:

* **Generator your password** (_not implemented_).
* **Generator your email** (_not implemented_).
* **Generator your information** (_not implemented_).
"""


app = FastAPI(
    title="H4ck1ng",
    description=description,
    version="0.0.1",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Rich Nguyen",
        "url": "https://github.com/minhgiau998",
        "email": "minhgiau04041998@gmail.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_tags=tags_metadata,
)


@app.get("/", tags=["Home"])
def get_root() -> dict:
    return {"message": "Welcome to the h4ck1ng server."}


@app.post(
    "/hacking/track_phone_number_location",
    tags=["Hacking"],
    response_model=TrackPhoneNumberLocationResponseModel,
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "location": "Ho Chi Minh City",
                    }
                }
            },
        },
        422: {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "example": {
                        "phone_number": "+842873005588",
                        "country_code": "en",
                    }
                }
            },
        },
    },
)
def post_track_phone_number_location(
    track_phone_number_location_request_model: TrackPhoneNumberLocationRequestModel,
) -> dict:
    try:
        ch_number = phonenumbers.parse(
            track_phone_number_location_request_model.phone_number, "CH"
        )
        location = {
            "location": geocoder.description_for_number(
                ch_number, track_phone_number_location_request_model.country_code
            )
        }
        data = jsonable_encoder(location)
        return JSONResponse(content=data)
    except NumberParseException:
        raise HTTPException(
            status_code=422,
            detail="Phone number {} is not valid".format(
                track_phone_number_location_request_model.phone_number
            ),
        )


@app.post(
    "/hacking/email-finder",
    tags=["Hacking"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "status": "valid",
                            "result": "deliverable",
                            "_deprecation_notice": "Using result is deprecated, use status instead",
                            "score": 100,
                            "email": "lynn@fpt.com.vn",
                            "regexp": True,
                            "gibberish": False,
                            "disposable": False,
                            "webmail": False,
                            "mx_records": True,
                            "smtp_server": True,
                            "smtp_check": True,
                            "accept_all": False,
                            "block": False,
                            "sources": [
                                {
                                    "domain": "giaiphapbenhvien.com",
                                    "uri": "http://giaiphapbenhvien.com/tu-dien-dong-duoc/233-benh-vien/hung-yen/399-trung-tam-y-te-van-giang.html",
                                    "extracted_on": "2020-11-15",
                                    "last_seen_on": "2021-05-15",
                                    "still_on_page": False,
                                },
                                {
                                    "domain": "giaiphapbenhvien.com",
                                    "uri": "http://giaiphapbenhvien.com/233-benh-vien/hung-yen/399-trung-tam-y-te-van-giang.html",
                                    "extracted_on": "2020-10-31",
                                    "last_seen_on": "2021-05-01",
                                    "still_on_page": False,
                                },
                                {
                                    "domain": "giaiphapbenhvien.com",
                                    "uri": "http://giaiphapbenhvien.com/y-duoc/233-benh-vien/hung-yen/399-trung-tam-y-te-van-giang.html",
                                    "extracted_on": "2019-06-17",
                                    "last_seen_on": "2021-04-18",
                                    "still_on_page": False,
                                },
                                {
                                    "domain": "giaiphapbenhvien.com",
                                    "uri": "http://giaiphapbenhvien.com/tra-cuu-thuoc-tay/233-benh-vien/hung-yen/399-trung-tam-y-te-van-giang.html",
                                    "extracted_on": "2019-06-04",
                                    "last_seen_on": "2021-04-14",
                                    "still_on_page": False,
                                },
                                {
                                    "domain": "giaiphapbenhvien.com",
                                    "uri": "http://giaiphapbenhvien.com/danh-ba-benh-vien/233-benh-vien/hung-yen/399-trung-tam-y-te-van-giang.html",
                                    "extracted_on": "2019-04-08",
                                    "last_seen_on": "2021-04-17",
                                    "still_on_page": False,
                                },
                            ],
                        },
                        "meta": {"params": {"email": "lynn@fpt.com.vn"}},
                    }
                }
            },
        },
        422: {
            "description": "Validation Error",
            "content": {"application/json": {"example": {"email": "dunt3@fpt.com.vn"}}},
        },
    },
)
def post_email_finder(email_finder_request_model: EmailFinderRequestModel) -> dict:
    email = email_finder_request_model.email
    api_key = "c5cc676034b0dd5a9f5754d902feae861880f207"
    url = "https://api.hunter.io/v2/email-verifier?email={}&api_key={}".format(
        email, api_key
    )
    response = requests.get(url)
    data = jsonable_encoder(response.json())
    return JSONResponse(content=data)


@app.post(
    "/security/web-vulnerability-scanner",
    tags=["Security"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "xst": {
                            "message": "This site seems vulnerable to Cross Site Tracing (XST)!"
                        },
                        "lfi": {
                            "message": "This site seems not vulnerable to Local File Inclusion (LFI)!"
                        },
                        "sql_time_based": {
                            "message": "This site seems not vulnerable to Blind SQL injection time based!"
                        },
                        "sql_error_based": {
                            "message": "This site seems vulnerable to Blind SQL injection error based!",
                            "payload": "'",
                            "poc": "http://demo.testfire.net/='",
                        },
                        "xss": {
                            "message": "This site seems not vulnerable to Cross Site Scripting (XSS)!"
                        },
                        "waf": {"message": "No WAF detected!"},
                    }
                }
            },
        },
        404: {
            "description": "Not Found",
            "content": {
                "application/json": {
                    "example": {"url": "https://www.example.com/products.php?id=1"}
                }
            },
        },
        422: {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "example": {"url": "https://www.example.com/products.php?id=1"}
                }
            },
        },
    },
)
def post_web_vulnerability_scanner(
    web_vulnerability_scanner_request_model: WebVulnerabilityScannerRequestModel,
) -> dict:
    url = web_vulnerability_scanner_request_model.url
    if validators.url(url):
        # Check website is alive
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            # Cross Site Tracing (XST) test.
            print("\n[*] Testing Cross Site Tracing (XST)")
            headers = {"Test": "Hello_Word"}
            req = requests.get(url, headers=headers)
            head = req.headers
            if "Test" or "test" in head:
                xst = {
                    "message": "This site seems vulnerable to Cross Site Tracing (XST)!"
                }
            else:
                xst = {
                    "message": "This site seems not vulnerable to Cross Site Tracing (XST)!"
                }
            print("[+] {}".format(xst["message"]))

            # Local File Inclusion (LFI) test.
            print("\n[*] Testing Local File Inclusion (LFI)")
            payloads = [
                "../etc/passwd",
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd",
                "../../../../../../../../etc/passwd",
            ]
            urlt = url.split("=")
            urlt = urlt[0] + "="
            for pay in payloads:
                uur = urlt + pay
                req = requests.get(uur).text
                if "root:x:0:0" in req:
                    lfi = {
                        "message": "This site seems vulnerable to Local File Inclusion (LFI)!",
                        "payload": pay,
                        "poc": uur,
                    }
                    print("[+] {}".format(lfi["message"]))
                    print("[+] Payload: {}".format(lfi["payload"]))
                    print("[+] POC: {}".format(lfi["poc"]))
                    break
                else:
                    lfi = None
                    pass
            if lfi is None:
                lfi = {
                    "message": "This site seems not vulnerable to Local File Inclusion (LFI)!"
                }
                print("[+] {}".format(lfi["message"]))

            # SQL injection time based test.
            print("\n[*] Testing SQL injection time based")
            urlt = url.split("=")
            urlt = urlt[0] + "="
            urlb = urlt + "1-SLEEP(2)"
            time1 = time.time()
            req = requests.get(urlb)
            time2 = time.time()
            timet = time2 - time1
            timet = str(timet)
            timet = timet.split(".")
            timet = timet[0]
            if int(timet) >= 2:
                sql_time_based = {
                    "message": "This site seems vulnerable to Blind SQL injection time based!",
                    "payload": "1-SLEEP(2)",
                    "poc": urlb,
                }
                print("[+] {}".format(sql_time_based["message"]))
                print("[!] Payload:", "1-SLEEP(2)")
                print("[!] POC:", urlb)
            else:
                sql_time_based = {
                    "message": "This site seems not vulnerable to Blind SQL injection time based!",
                }
                print("[+] {}".format(sql_time_based["message"]))

            # SQL injection error based test.
            payload1 = "'"
            urlq = urlt + payload1
            reqqq = requests.get(urlq).text
            if (
                "mysql_fetch_array()"
                or "You have an error in your SQL syntax"
                or "error in your SQL syntax"
                or "mysql_numrows()"
                or "Input String was not in a correct format"
                or "mysql_fetch"
                or "num_rows"
                or "Error Executing Database Query"
                or "Unclosed quotation mark"
                or "Error Occured While Processing Request"
                or "Server Error"
                or "Microsoft OLE DB Provider for ODBC Drivers Error"
                or "Invalid Querystring"
                or "VBScript Runtime"
                or "Syntax Error"
                or "GetArray()"
                or "FetchRows()" in reqqq
            ):
                sql_error_based = {
                    "message": "This site seems vulnerable to Blind SQL injection error based!",
                    "payload": payload1,
                    "poc": urlq,
                }
                print("\n[+] {}".format(sql_error_based["message"]))
                print("[+] Payload: {}".format(sql_error_based["payload"]))
                print("[+] POC: {}".format(sql_error_based["poc"]))
            else:
                sql_error_based = None
                pass
            if sql_error_based is None:
                sql_error_based = {
                    "message": "This site seems not vulnerable to Blind SQL injection error based!"
                }
                print("[+] {}".format(sql_error_based["message"]))

            # Cross Site Scripting (XSS) tests.
            paydone = []
            payloads = [
                "injectest",
                "/inject",
                "//inject//",
                "<inject",
                "(inject",
                '"inject',
                '<script>alert("inject")</script>',
            ]
            print("[*] Testing XSS")
            print("[+] 10 Payloads.")

            urlt = url.split("=")
            urlt = urlt[0] + "="
            for pl in payloads:
                urlte = urlt + pl
                re = requests.get(urlte).text
                if pl in re:
                    paydone.append(pl)
                else:
                    pass
            url1 = (
                urlt + "%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb"
            )
            req1 = requests.get(url1).text
            if "'>inject<svg/onload=confirm(/inject/)>web" in req1:
                paydone.append(
                    "%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb"
                )
            else:
                pass

            url2 = urlt + "%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E"
            req2 = requests.get(url2).text
            if '<script>alert("inject")</script>' in req2:
                paydone.append("%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E")
            else:
                pass

            url3 = urlt + "%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E"
            req3 = requests.get(url3).text
            if '<script>alert("inject")</script>' in req3:
                paydone.append("%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E")
            else:
                pass

            if len(paydone) == 0:
                xss = {
                    "message": "This site seems not vulnerable to Cross Site Scripting (XSS)!"
                }
                print("[-] {}".format(xss["message"]))
            else:
                xss = {
                    "message": "This site seems vulnerable to Cross Site Scripting (XSS)!",
                    "payloads": [],
                }
                print("[+]", len(paydone), "Payloads were found.")
                for p in paydone:
                    xss["payloads"].append({"payload": p, "poc": urlt + p})
                    print("[!] Payload: {}".format(p))
                    print("[!] POC: {}".format(urlt + p))

            # Web Application Firewall (WAF) detection.
            print("\n[*] Testing WAF")
            try:
                sc = requests.get(url)
                if sc.status_code == 200:
                    sc = sc.status_code
                else:
                    print("[-] Error with status code:", sc.status_code)
            except:
                print("[-] Error with the first request.")
                exit()
            r = requests.get(url)

            opt = ["Yes", "yes", "Y", "y"]
            try:
                if r.headers["server"] == "cloudflare":
                    print(
                        "[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server."
                    )
                    ex = input("[\033[1;31m!\033[0;0m]Exit y/n: ")
                    if ex in opt:
                        exit("[\033[1;33m!\033[0;0m] - Quitting")
            except:
                pass

            noise = "?=<script>alert()</script>"
            fuzz = url + noise
            waffd = requests.get(fuzz)
            if (
                waffd.status_code == 406
                or waffd.status_code == 501
                or waffd.status_code == 999
                or waffd.status_code == 419
                or waffd.status_code == 403
            ):
                waf = {"message": "WAF detected!"}
            else:
                waf = {"message": "No WAF detected!"}
            print("[+] {}".format(waf["message"]))

            # Data
            web_vulnerability_scanner = {
                "xst": xst,
                "lfi": lfi,
                "sql_time_based": sql_time_based,
                "sql_error_based": sql_error_based,
                "xss": xss,
                "waf": waf,
            }
            data = jsonable_encoder(web_vulnerability_scanner)
            return JSONResponse(content=data)
        else:
            raise HTTPException(
                status_code=404,
                detail="URL {} is not found".format(
                    web_vulnerability_scanner_request_model.url
                ),
            )

    else:
        raise HTTPException(
            status_code=422,
            detail="URL {} is not valid".format(
                web_vulnerability_scanner_request_model.url
            ),
        )


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
    "/network/geo-ip",
    tags=["Network"],
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
def post_geo_ip(geo_ip_request_model: GeoIpRequestModel) -> dict:
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


@app.post(
    "/network/port-forward",
    tags=["Network"],
    response_model=PortForwardResponseModel,
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Port 80 is closed on 1.1.1.1",
                    }
                }
            },
        },
        422: {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "example": {
                        "ip_address": "1.1.1.1",
                        "port": 80,
                    }
                }
            },
        },
    },
)
def post_port_forward(port_forward_request_model: PortForwardRequestModel) -> dict:
    try:
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = (
            port_forward_request_model.ip_address,
            port_forward_request_model.port,
        )
        result_of_check = a_socket.connect_ex(location)
        if result_of_check == 0:
            status = "opened"
        else:
            status = "closed"
        data = {
            "message": "Port {} is {} on {}".format(
                port_forward_request_model.port,
                status,
                port_forward_request_model.ip_address,
            )
        }
        return JSONResponse(content=data)
    except OverflowError:
        raise HTTPException(
            status_code=422,
            detail="Port {} is not valid".format(port_forward_request_model.port),
        )
    except socket.gaierror:
        raise HTTPException(
            status_code=422,
            detail="IP address {} is not valid".format(
                port_forward_request_model.ip_address
            ),
        )
