DJ Sam
======

**Spinning all your favorite SAML hits.**

*RHEL 7 on AWS*

selinux
-------

::

    [ec2-user@ip-172-30-2-147 ~]$ cat /etc/selinux/config 

    # This file controls the state of SELinux on the system.
    # SELINUX= can take one of these three values:
    #     enforcing - SELinux security policy is enforced.
    #     permissive - SELinux prints warnings instead of enforcing.
    #     disabled - No SELinux policy is loaded.
    SELINUX=permissive
    # SELINUXTYPE= can take one of three two values:
    #     targeted - Targeted processes are protected,
    #     minimum - Modification of targeted policy. Only selected processes are protected. 
    #     mls - Multi Level Security protection.
    SELINUXTYPE=targeted

RHEL 7
------

::

    sudo yum groupinstall "Development Tools" -y
    sudo yum install httpd mod_wsgi git python2-pip python-virtualenv -y

    # Certbot requires epel repo & zope interface RPM from vendor/
    rpm -Uvh python-zope-interface-4.0.5-4.el7.x86_64.rpm 
    sudo yum install python2-certbot-apache certbot

    sudo yum install libjpeg-devel
    sudo yum install screen
    sudo yum install swig
    sudo yum install libffi-devel
    sudo yum install openssl-devel

    # xmlsec requires RPMs from vendor/
    sudo rpm -Uvh xmlsec1-1.2.20-5.el7.x86_64.rpm 
    sudo rpm -Uvh xmlsec1-devel-1.2.20-5.el7.x86_64.rpm 
    sudo rpm -Uvh xmlsec1-openssl-1.2.20-5.el7.x86_64.rpm 
    sudo rpm -Uvh xmlsec1-openssl-devel-1.2.20-5.el7.x86_64.rpm 

Apache
------

::

    …

    WSGIScriptAlias / /srv/django-saml-test/project/wsgi.py
    <Directory /srv/django-saml-test/project>
            <Files wsgi.py>
                    Require all granted
            </Files>
    </Directory>
    </VirtualHost>

    WSGIPythonHome /srv/django-saml-test
    WSGIPythonPath /srv/django-saml-test

SAML response examples
----------------------

OneLogin SAMLResponse
~~~~~~~~~~~~~~~~~~~~~

::

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
                <ds:SignatureValue>BvY9Q7tHhiZSEuSuK4XrQ9Bqm8ItdG8I3mZbMvPYb8SmM9OrOVa5+jD05nn528jk+Zzbg6jSBKFplz1mlXnXJKeaJTBDVcV8nVnzojaj6P+WgUNOivl+oVh86mhy7+xQVpiPwHvz2PLwKP4vGW8YlWShoWMQCbqyDnGD4qAU94l1RRCQ8TvuD+qHyqQhuQK3T26dXTh/W04oB8WIQv6k//07dwF5zNRb/I5BZ/dtTZR8rr+cJG441+DFIc+4uQ3h9q3IHE0kSl7TQUky7akOdRnvB1ZZx8IhRdM7e7EvJYL+bbSrgizi18pPt4UMk+s2+NkNaK/ADvGQXEvVaaoYVw==</ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>MIIEHTCCAwWgAwIBAgIUGM9vFCkZxTmjpgMg4m3sqHXseiAwDQYJKoZIhvcNAQEFBQAwWjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCUFDTEFSS05FVDEVMBMGA1UECwwMT25lTG9naW4gSWRQMSAwHgYDVQQDDBdPbmVMb2dpbiBBY2NvdW50IDEwNjgwMzAeFw0xNzA1MTUyMjI0NTNaFw0yMjA1MTYyMjI0NTNaMFoxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlBQ0xBUktORVQxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEgMB4GA1UEAwwXT25lTG9naW4gQWNjb3VudCAxMDY4MDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIgZRhLBwDK4MjQ8+d7KrDQ9wJif1kcvbRhmWjoBiapjPrx+LLIWlzeZy2IjHHvEG9n+FbWgRHgs8V+uPcgjiwiQBFt7nDx3bcyvcAjv8h8FPWNoLRuHPX8uJdwJ4BLFLCe5ADalgNzU0+QTiREJYqqv43snTgovTxcGmEUSi5tAsV5s3JYV0m9UlfNnwRBkMSvTCMh2HhEyqK5ETdifXLp1WLWtEqUlMAf+4QYCWBSswjKlciF0/BWIziaZjLwfDe2fbfulcQDsFkw5f7clqka8P1kxxZSTWqCuIVx+yyV+AC5vRYVmY9s5YPKFtaMMi8Vn64NpMCw1z44cK8ct8tAgMBAAGjgdowgdcwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUpSE3UpRUUob9RTyGkfOZpd5lqqIwgZcGA1UdIwSBjzCBjIAUpSE3UpRUUob9RTyGkfOZpd5lqqKhXqRcMFoxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlBQ0xBUktORVQxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEgMB4GA1UEAwwXT25lTG9naW4gQWNjb3VudCAxMDY4MDOCFBjPbxQpGcU5o6YDIOJt7Kh17HogMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAgUxGgSjpCiacIyXSU41nI6K+b02zhEJVeQV4QR1IESADpQXSSgDMmMJtaOijNrZ5n8WTb8CE0N6egA9VX5ff3hSXTLHqzgdGNHOxK2+gV0jUACs55k9ROJxNEs+GmY9iIwy0weljssHdiHDuoczk27pnbgz+dQo0jDo9P1vfQQZjhe3F7EsPNfdJDyYOrl6ysDetC/rnrHQaH14hld6nkTVIjtohx8qyu2Q2vqvd1ScD9PKTs1HBh2mEsWb+CYohMXZmD19qWjbzeEc1nbQM5BKp/WhAKi8a2SxkAB8eYy21oqgChCK/5fUocsOICVfaHT+BdhV6xz94FspUuBYf4g==</ds:X509Certificate>
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

dj-saml-idp SAMLResponse
~~~~~~~~~~~~~~~~~~~~~~~~

::

    <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_491b1d10265e4299939a48ff2c7235d0"
                    Version="2.0"
                    IssueInstant="2017-05-17T02:37:33Z"
                    Destination="https://aclark.myabsorb.com/account/saml"
                    >
        <saml:Issuer>https://dj-saml-idp.aclark.net</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        xmlns:xs="http://www.w3.org/2001/XMLSchema"
                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                        Version="2.0"
                        ID="_6e4052395852402cb48ff74fd6c1cde0"
                        IssueInstant="2017-05-17T02:37:33Z"
                        >
            <saml:Issuer>https://dj-saml-idp.aclark.net</saml:Issuer>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                    <ds:Reference URI="#_6e4052395852402cb48ff74fd6c1cde0">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                        <ds:DigestValue>zEWYGgLKLMLQ0LFGYJNDXBrVarM=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>P/UlY4rY7lctWWUS3LkRxDFCM3UcynowYXQn6WWIzODXA7sCe/9lXevY9mTEqQvdz7V2g84wBtNUho2MNBXUiAEma5qx3xZl2RVbRTdpJJO85oNsFIpxPBmY4PK1ObkH175sTdpYjZKhueln8cyGdKAUTNkbY1v/Zb5Cm5sZhmWD4mZkO3CI1DPx2L0coojxtmUMM6egor/op0LxE3vfMPQFWClAMmWh1daQ+V+JNk705G/4Y3JpP+/SDCEAMOojZeBhIc+QP46A2x91jC3JF8hLrOaO7CPIgL7OtgleG3XRvwlx/hxHUpOMFQXsVg2/7S+C8LR5DIsb1mtqeEmTugg=</ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>MIIDZTCCAkygAwIBAgIBADANBgkqhkiG9w0BAQ0FADBMMQswCQYDVQQGEwJ1czELMAkGA1UECAwCTUQxDzANBgNVBAoMBkFDTEFSSzEfMB0GA1UEAwwWZGotc2FtbC1pZHAuYWNsYXJrLm5ldDAeFw0xNzA1MTcwMDM4MzJaFw0xODA1MTcwMDM4MzJaMEwxCzAJBgNVBAYTAnVzMQswCQYDVQQIDAJNRDEPMA0GA1UECgwGQUNMQVJLMR8wHQYDVQQDDBZkai1zYW1sLWlkcC5hY2xhcmsubmV0MIIBIzANBgkqhkiG9w0BAQEFAAOCARAAMIIBCwKCAQIAykosgghQluMK9lIsnCfALlzqSTQUD/vqi+G+jllWdJrIiVFSA6qYHJaFJ3smQCpHDO8d8TMJMtEZQR/Jg6ETf+mumigoOVYkKDfSNKxwWSmH9JJXBXeM7vTXhzM0O7pqUoyRUvp8xnn1Jv0CERiRoA5EPCaFrXO670CViu/NLPzJA2epPS++OqbDzn+XZqSxCKAWwgj3IX4ash6Jsrk/Xgf4bVBSgVnZRZ9XTgMVnxu7B10jeTPoOwoshgCzEEZF+2m6GFmV/ACe8nCpv47rv8053lNeTDiDGHMBpoA0aICbvge3OLCsXnQqPY6z7KeST1tCD0H+VJyBce0FBIo3rYECAwEAAaNQME4wHQYDVR0OBBYEFEhUGuuba4Sbln4dijEB9nGKqsBIMB8GA1UdIwQYMBaAFEhUGuuba4Sbln4dijEB9nGKqsBIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQENBQADggECAFOa3vVl8GGxIZU0G8Ld9VPl9R7CRANLceNhg1p+IFcOn7lB6Iqy1T8g7Z1ic0+X/SSN3uwOWxTM/Yp4oZQ1eCtGRvmPBx9G+AhOoftaQxDzX/Ug5AOWcbawDffabVhPaPf7vrkNHWirToZ5cArOXZgoYnOm0tfq8W/T+ay+yuN3kgnAAFNsyiK6IE/4VbNlQReCQCnIapOyDlxc6tDBL4t37xCDlup4+aO6LnG1tDMnOVxj+0vQMWbaQ3k78YFEmH3fOZFyDpra42aVWYx0fbFjz+LoOElMrXTwmR6VUcJZdGnXvMwsKsxa+s5ct7Uc1wKD+Wcf1bEC1ueu9RmOqHMS</ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </ds:Signature>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">aclark@aclark.net</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2017-05-17T02:52:33Z"
                                                  Recipient="https://aclark.myabsorb.com/account/saml"
                                                  />
                </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore="2017-05-17T01:37:33Z"
                             NotOnOrAfter="2017-05-17T02:52:33Z"
                             >
                <saml:AudienceRestriction>
                    <saml:Audience/>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="2017-05-17T02:37:33Z"
                                 SessionNotOnOrAfter=""
                                 SessionIndex=""
                                 >
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
        </saml:Assertion>
    </samlp:Response>

dj-saml-idp SAMLResponse (dj-saml-sp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_93e01310a905437384f3a2e453866f07"
                    Version="2.0"
                    IssueInstant="2017-05-19T19:32:58Z"
                    Destination="http://127.0.0.1:9000/sp/acs/"
                    >
        <saml:Issuer>http://127.0.0.1:8000</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_d1ea256032b14327b5f39ad7f7090f54"
                        IssueInstant="2017-05-19T19:32:58Z"
                        Version="2.0"
                        >
            <saml:Issuer>http://127.0.0.1:8000</saml:Issuer>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                    <ds:Reference URI="#_d1ea256032b14327b5f39ad7f7090f54">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                        <ds:DigestValue>bgeIFEJ8MIj+HlzXicINqox2WSQ=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>ySTiOaFGtem6dp8gcKQq2W1UayxPz83N3bRDyllxcvkkfHReXDizZLUmIVNySCnHXqcsw/zRbNUV19XYr5OaFA==</ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </ds:Signature>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2017-05-19T19:47:58Z"
                                                  Recipient="http://127.0.0.1:9000/sp/acs/"
                                                  />
                </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore="2017-05-19T18:32:58Z"
                             NotOnOrAfter="2017-05-19T19:47:58Z"
                             >
                <saml:AudienceRestriction>
                    <saml:Audience>http://127.0.0.1:8000/idp/login/</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="2017-05-19T19:32:58Z">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
            <saml:AttributeStatement>
                <saml:Attribute Name="foo">
                    <saml:AttributeValue>bar</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
    </samlp:Response>

dj-saml-idp SAMLResponse (dj-saml-sp, pretty print)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    <?xml version="1.0"?>
    <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_93e01310a905437384f3a2e453866f07" Version="2.0" IssueInstant="2017-05-19T19:32:58Z" Destination="http://127.0.0.1:9000/sp/acs/">
      <saml:Issuer>http://127.0.0.1:8000</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_d1ea256032b14327b5f39ad7f7090f54" IssueInstant="2017-05-19T19:32:58Z" Version="2.0">
        <saml:Issuer>http://127.0.0.1:8000</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <ds:Reference URI="#_d1ea256032b14327b5f39ad7f7090f54">
              <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              <ds:DigestValue>bgeIFEJ8MIj+HlzXicINqox2WSQ=</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>ySTiOaFGtem6dp8gcKQq2W1UayxPz83N3bRDyllxcvkkfHReXDizZLUmIVNySCnHXqcsw/zRbNUV19XYr5OaFA==</ds:SignatureValue>
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </ds:Signature>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="2017-05-19T19:47:58Z" Recipient="http://127.0.0.1:9000/sp/acs/"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2017-05-19T18:32:58Z" NotOnOrAfter="2017-05-19T19:47:58Z">
          <saml:AudienceRestriction>
            <saml:Audience>http://127.0.0.1:8000/idp/login/</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2017-05-19T19:32:58Z">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name="foo">
            <saml:AttributeValue>bar</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>

Research
--------

- http://research.aurainfosec.io/bypassing-saml20-SSO/
- https://github.com/onelogin/python-saml/issues/30
- https://github.com/onelogin/python-saml/issues/166
- http://python-saml.readthedocs.io/en/latest/
