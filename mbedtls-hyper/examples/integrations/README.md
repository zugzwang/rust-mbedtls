HTTPS server example using mbedtls, Fortanix Enclave Manager and Fortanix SDKMS. 

It shows a few things:
- generating a certificate within the enclave and using Fortanix Enclave Manager to sign it.
- setting up ticket context for faster ssl client reconnects.
- JSON API to store objects in SDKMS.

Usage:

1. Get an account on https://em.fortanix.com
2. Set up a node agent machine to run the example on: https://support.fortanix.com/hc/en-us/articles/360043085652-User-s-Guide-Compute-Nodes#NodeAgent
3. Update './config' with credentials and domain you want to use.
4. Update domain in './src/main.rs', line: "    let domain = "localhost";"
5. Register and build the app.
```
./register_and_build.sh ./config
```
This will also download the account CA public key.

5. Configure Fortanix SDKMS to allow access for the application - https://sdkms.fortanix.com
5.1. Create/select an account that you want the application to manage.
5.2. Go to settings - Administrative Apps - Add Administrative App.
5.3. Select authentication method: Trusted CA
5.4. Enter the domain you want as common name. (the one from ./config)
5.5. Copy the contents of ./artifacts/zone_ca.crt in box below.
5.6. Press 'Create'
5.7. Click on the newly create application.
5.8. Copy the UUID associated with it and place it in src/main.rs, line: let api_key = "4bea4ed2-4025-4392-a54c-a5f98ee55a07";
More info at: https://support.fortanix.com/hc/en-us/articles/360033272171-User-s-Guide-Authentication#1.7CreateApplicationsandGroupsProgrammaticallyusingAppAuthenticationMethods

6. copy the 'sgxs' file to the node agent machine.
7. run the binary on the node agent machine.
```
ftxsgx-runner /path/to/$binary_name.sgxs
```

8. When running the application will give out a line like this:

```
Listening on address: 127.0.0.1:8080 for host localhost
To test with curl: 

# curl --cacert ./artifacts/zone_ca.crt --resolve localhost:8080:127.0.0.1 -X POST -d '{ "id": "key-id", "value": "secret" } ' https://localhost:8080/sdkms
```

9. Running the CURL command results in an SDKMS object being created and metadata returned:

```
{
  "acct_id": "cfb2c30b-98ca-42b4-af91-1a5c9ff25d83",
  "activation_date": "20201116T165504Z",
  "compromise_date": null,
  "created_at": "20201116T165504Z",
  "creator": {
    "app": "4bea4ed2-4025-4392-a54c-a5f98ee55a07"
  },
  "custom_metadata": null,
  "deactivation_date": null,
  "description": null,
  "deterministic_signatures": null,
  "elliptic_curve": null,
  "enabled": true,
  "fpe": null,
  "key_ops": [
    "EXPORT",
    "APPMANAGEABLE"
  ],
  "key_size": 48,
  "kid": "2bad6ff2-0b80-4f19-9bb7-203e1ae65e81",
  "lastused_at": "19700101T000000Z",
  "links": null,
  "name": "key-id",
  "never_exportable": false,
  "obj_type": "SECRET",
  "origin": "External",
  "pub_key": null,
  "public_only": false,
  "publish_public_key": null,
  "revocation_reason": null,
  "rsa": null,
  "state": "Active",
  "transient_key": null,
  "value": null,
  "group_id": "1ceb01a6-2531-480e-8002-57ab0c6f3425"
}
```