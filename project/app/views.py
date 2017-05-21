from django.shortcuts import render
from lxml import etree
import base64
import os

SAML2_RESPONSE_ISSUER = 'https://dj-saml-idp.aclark.net'
SAML2_RESPONSE_DEST_URL = {
    'absorb': 'https://aclark.myabsorb.com/account/saml',
    'testshib': 'https://sp.testshib.org/Shibboleth.sso/SAML2/POST',
}
SAML2_RESPONSE_PRINCIPAL = 'aclark@aclark.net'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PUBLIC_CERT = os.path.join(BASE_DIR, 'certificate.crt')
PRIVATE_KEY = os.path.join(BASE_DIR, 'private.key')

cert = open(PUBLIC_CERT).read()
cert.replace('-----BEGIN CERTIFICATE-----', '')
cert.replace('-----END CERTIFICATE-----', '')
key = open(PRIVATE_KEY).read()

SAML2_RESPONSE = """
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="R7160360b378fef81d99fa54c6e0a4aa5c9c1a015"
                Version="2.0"
                IssueInstant="2017-05-16T23:34:33Z"
                Destination="{recipient}"
                >
    <saml:Issuer>https://app.onelogin.com/saml/metadata/658891</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    Version="2.0"
                    ID="pfx89aab9e8-af3e-ace9-97b6-c1086f076d7a"
                    IssueInstant="2017-05-16T23:34:33Z"
                    >
        <saml:Issuer>https://app.onelogin.com/saml/metadata/658891</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                <ds:Reference URI="#pfx89aab9e8-af3e-ace9-97b6-c1086f076d7a">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                    <ds:DigestValue>SQDekGp/Ibp90eC3O5dwu37ZdJA=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>%s</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">aclark@aclark.net</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2017-05-16T23:37:33Z"
                                              Recipient="{recipient}"
                                              />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2017-05-16T23:31:33Z"
                         NotOnOrAfter="2017-05-16T23:37:33Z"
                         >
            <saml:AudienceRestriction>
                <saml:Audience/>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2017-05-16T23:34:32Z"
                             SessionNotOnOrAfter="2017-05-17T23:34:33Z"
                             SessionIndex="_b49f0e60-1cbb-0135-39ae-06cb00433bb7"
                             >
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>
""" % cert


def home(request):
    """
    """

    destination = request.GET.get('destination')
    if destination:
        destination = SAML2_RESPONSE_DEST_URL[destination]
    else:
        destination = SAML2_RESPONSE_DEST_URL['absorb']

    # http://stackoverflow.com/a/3974112
    root = etree.fromstring(SAML2_RESPONSE)
    saml_response_pretty = etree.tostring(root, pretty_print=True)

    context = {
        'base64_encoded_saml_response': base64.b64encode(SAML2_RESPONSE),
        'saml_response': saml_response_pretty,
        'saml2_response_destination': destination,
    }
    return render(request, 'home.html', context)

    context = {
        'base64_encoded_saml_response': SAML2_RESPONSE,
    }
    return render(request, 'home.html', context)
