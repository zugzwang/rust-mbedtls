HTTPS server example using mbedtls.

To build with docker:
```
docker build -t server-example .
```

To run with docker:
```
docker run -p 9001:9001/tcp -v /var/run/aesmd:/var/run/aesmd --device /dev/isgx -it server-example
```


It shows a few things:
- SNI based HTTPS server - to allow virtual hosts using different certificates based on provided SNI.
- quick JSON parsing/reply
- setting up ticket context for faster ssl client reconnects.

1. To start:

Use either: ./run-sgx.sh or ./run-nonsgx.sh

This will print out a log line similar to:
```
To test with curl: 

# curl --cacert ./src/certificates/ca.pem --resolve mbedtls.example:42371:127.0.0.1 -X POST -d '{ "name": "john doe" } ' https://mbedtls.example:42371/test
```

2. Send a test request:

(Copy requst from program output)
```
# curl --cacert ./src/certificates/ca.pem --resolve mbedtls.example:42371:127.0.0.1 -X POST -d '{ "name": "john doe" } ' https://mbedtls.example:42371/test
```

This will use curl to:
- validate the HTTPS server certificate via --cacert
- override dns lookup for mbedtls.example domain towards 127.0.0.1
- post a simple JSON { "name": "john doe" } to a server control URL.

Resonse from server will be:

```
{"status":"Found person: john doe"}
```

