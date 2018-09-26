# Acceptance-tool

Acceptance tool contains the business tests required for the CloudTrust appliance: sign-on, single sign-on, logout, access control, claim augmentations, etc., both for the 
SAML and WSFED protocols.

## Prerequisites

Before being able to launch the tests, one needs:
- one instance of Keycloak that acts as IDP or as broker IDP in the broker test cases
- one instance of Keycloak that acts as external IDP 
- 8 service providers (SPs), 4 SAML and 4 WSFED, that are used for different tests

The config file for both the IDP and SP is located at `tests_config/dev.json`. 
Pay attention that the config file follows the realms settings (i.e. name of clients, port, ip)
and if you need to change these values you need to import the realm and change the settings accordingly.
 
 
The two keycloak instances need to have the following modules installed: 
- [keycloak-wsfed](https://github.com/cloudtrust/keycloak-wsfed)
- [keycloak-authorization](https://github.com/cloudtrust/keycloak-authorization)
- [keycloak-export](https://github.com/cloudtrust/keycloak-export) 
- [keycloak-client-mappers](https://github.com/cloudtrust/keycloak-client-mappers) 

 
## Setup

```Bash
git clone git@github.com:cloudtrust/acceptance-tool.git
python3 -m venv acceptance-tool
cd acceptance-tool
source bin/activate
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

In order to run the tests, there are two realms prepared (one for the broker and one for the external IDP) that contain all the clients, users, roles, attributes needed for the tests.
At every launch of the tests, two fixtures that import the realms are executed.
The realms are located at `tests_config/test_realm.json` and `tests_config/test_realm_external.json` and the fixtures perform an import of the realm 
representation found in these JSON files.  

  
## Run tests

In order to launch the SAML tests, please execute the following command:

```
python3 -m pytest tests/business_tests/saml_tests/ -vs --config-file tests_config/dev.json --standard SAML 

```

The paremeter **-v** and **-s** are used to increase the verbosity. Parameter **--config-file** provides the path to the configuration file. 
Parameter **--standard** gives the connection protocol. This parameter is needed only for the logout tests, where we need to login before starting 
the test and we need to say what connection protocol is used.

In order to launch the WSFED tests, please execute the foolowing command:

```
python3 -m pytest tests/business_tests/wsfed_tests/ -vs --config-file tests_config/dev.json --standard WSFED
```

Parameters used are the same as for the SAML tests. 

For launching individual test, one needs just to give the name of the test: 
```
python3 -m pytest -vs tests/business_tests/saml_tests/test_CT_TC_SAML_BROKER_ACCESS_CONTROL_RBAC_OK.py --config-file tests_config/dev.json
```


