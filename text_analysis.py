import json
from ibm_watson import NaturalLanguageUnderstandingV1
from ibm_watson.natural_language_understanding_v1 import Features, EmotionOptions, SentimentOptions
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator

def analyze_text(text):
    authenticator = IAMAuthenticator('<API_KEY>')
    natural_language_understanding = NaturalLanguageUnderstandingV1(
        version='2022-03-01',
        authenticator=authenticator
    )

    natural_language_understanding.set_service_url('<SERVICE_URL>')

    response = natural_language_understanding.analyze(
        text=text,
        features=Features(
            emotion=EmotionOptions(),
            sentiment=SentimentOptions()
        )
    ).get_result()

    return json.dumps(response)
