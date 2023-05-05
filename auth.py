from secrets_keeper import (
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    OAUTH2_AUTHORIZATION_URI,
    OAUTH2_ACCESS_REFRESH_TOKEN_REQUEST_URI,
    # apo_access_token,
    semo_access_token,
    # apo_refresh_token,
    semo_refresh_token,
    semo_user_id,
)
import requests
import hashlib
import base64
import secrets

code_verifier = secrets.token_urlsafe(64)
APP_STATE = secrets.token_urlsafe(64)
code_challenge = (
    base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
    .decode()
    .rstrip("=")
)

authorization_url = (
    f"{OAUTH2_AUTHORIZATION_URI}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=activity+"
    f"cardio_fitness+electrocardiogram+heartrate+location+nutrition+oxygen_saturation+profile+respiratory_rate+settings"
    f"+sleep+social+temperature+weight&code_challenge_method=S256&code_challenge={code_challenge}&state={APP_STATE}"
)

authorizatin_response_code = requests.get(authorization_url)


def strip_authorization_code_from_authorization_response(authorization_response: str):
    return authorization_response.split("code=")[1].split("&state")[0]


def strip_app_state_from_authorization_response(authorization_response: str):
    return authorization_response.split("state=")[1].split("#_=_")[0]


def create_access_token(authorization_code: str):
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    response = requests.post(
        OAUTH2_ACCESS_REFRESH_TOKEN_REQUEST_URI,
        data=data,
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    return response.json()


if __name__ == "__main__":
    print(code_verifier)
    print(code_challenge)
    print(authorization_url)
    response_url = input("Enter the redirect url here: ")
    authorization_code = strip_authorization_code_from_authorization_response(
        response_url
    )
    app_state = strip_app_state_from_authorization_response(response_url)
    if app_state != APP_STATE:
        raise ValueError("App state is not valid!")
    access_refresh_token = create_access_token(authorization_code)
    print(access_refresh_token)
    access_token = access_refresh_token["access_token"]
    refresh_token = access_refresh_token["refresh_token"]
    token_type = access_refresh_token["token_type"]
    user_id = access_refresh_token["user_id"]

    try:
        response = requests.get(
            f"https://api.fitbit.com/1/user/{semo_user_id}/profile.json",
            headers={"authorization": f"Bearer {semo_access_token}"},
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": semo_refresh_token,
            "expires_in": 28800,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        response = requests.post(OAUTH2_ACCESS_REFRESH_TOKEN_REQUEST_URI, data=data)
        response.raise_for_status()
        response_json = response.json()
        semo_access_token = response_json["access_token"]
        semo_refresh_token = response_json["refresh_token"]
        token_type = response_json["token_type"]
        user_id = response_json["user_id"]
        expires_in = response_json["expires_in"]

        response_from_fitbit = requests.get(
            f"https://api.fitbit.com/1/user/{semo_user_id}/profile.json",
            headers={"authorization": f"{token_type} {semo_access_token}"},
        )
        response_from_fitbit.raise_for_status()
        print(response_from_fitbit.json())

    # response.raise_for_status()
    # print(response.json())
